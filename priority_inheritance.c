/*
 * priority_inheritance.c - Priority Inheritance Protocol Implementation
 *
 * Implements the Priority Inheritance Protocol (PIP) where a low-priority
 * process holding a resource temporarily inherits the priority of any
 * higher-priority process blocked waiting for that resource.
 *
 * This prevents unbounded priority inversion by ensuring the holder
 * runs at the maximum priority of any waiting process.
 */

#include "priority_inversion.h"
#include "../include/kernel.h"
#include "../include/process.h"
#include "../include/interrupts.h"
#include <string.h>

/* Resource table */
static pi_resource_t resources[PI_MAX_RESOURCES];

/* Process info table */
static pi_process_info_t processes[PI_MAX_PROCESSES];

/* Wait entry pool */
#define WAIT_POOL_SIZE 512
static pi_wait_entry_t wait_pool[WAIT_POOL_SIZE];
static pi_wait_entry_t *free_wait_entries = NULL;

/* System state */
static pi_system_state_t system_state;

static pi_wait_entry_t *alloc_wait_entry(void);
static void free_wait_entry(pi_wait_entry_t *entry);
static void insert_wait_queue(pi_resource_t *res, pi_wait_entry_t *entry);
static pi_wait_entry_t *remove_wait_queue_head(pi_resource_t *res);
static void remove_from_wait_queue(pi_resource_t *res, pid32 pid);
static void propagate_priority(pid32 pid);
static void recalculate_priority(pid32 pid);
static uint32_t get_max_waiting_priority(pi_resource_t *res);
static bool detect_cycle(pid32 start_pid, int32_t target_resource);
static void add_held_resource(pid32 pid, int32_t resource_id);
static void remove_held_resource(pid32 pid, int32_t resource_id);
static pi_process_info_t *get_process_info(pid32 pid);
static pi_resource_t *get_resource(int32_t id);

/**
 * Allocate wait entry from pool
 */
static pi_wait_entry_t *alloc_wait_entry(void)
{
    if (free_wait_entries == NULL) {
        return NULL;
    }
    
    pi_wait_entry_t *entry = free_wait_entries;
    free_wait_entries = free_wait_entries->next;
    
    memset(entry, 0, sizeof(pi_wait_entry_t));
    return entry;
}

/**
 * Return wait entry to pool
 */
static void free_wait_entry(pi_wait_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }
    entry->next = free_wait_entries;
    free_wait_entries = entry;
}

/**
 * Insert entry into wait queue (sorted by priority, descending)
 */
static void insert_wait_queue(pi_resource_t *res, pi_wait_entry_t *entry)
{
    if (res == NULL || entry == NULL) {
        return;
    }
    
    entry->next = NULL;
    
    /* Empty queue */
    if (res->wait_queue == NULL) {
        res->wait_queue = entry;
        res->wait_count = 1;
        return;
    }
    
    /* Find insertion point (sorted by priority, descending) */
    pi_wait_entry_t *prev = NULL;
    pi_wait_entry_t *curr = res->wait_queue;
    
    while (curr != NULL && curr->priority >= entry->priority) {
        prev = curr;
        curr = curr->next;
    }
    
    if (prev == NULL) {
        /* Insert at head */
        entry->next = res->wait_queue;
        res->wait_queue = entry;
    } else {
        /* Insert after prev */
        entry->next = prev->next;
        prev->next = entry;
    }
    
    res->wait_count++;
}

/**
 * Remove and return head of wait queue
 */
static pi_wait_entry_t *remove_wait_queue_head(pi_resource_t *res)
{
    if (res == NULL || res->wait_queue == NULL) {
        return NULL;
    }
    
    pi_wait_entry_t *head = res->wait_queue;
    res->wait_queue = head->next;
    head->next = NULL;
    res->wait_count--;
    
    return head;
}

/**
 * Remove specific process from wait queue
 */
static void remove_from_wait_queue(pi_resource_t *res, pid32 pid)
{
    if (res == NULL || res->wait_queue == NULL) {
        return;
    }
    
    pi_wait_entry_t *prev = NULL;
    pi_wait_entry_t *curr = res->wait_queue;
    
    while (curr != NULL) {
        if (curr->pid == pid) {
            if (prev == NULL) {
                res->wait_queue = curr->next;
            } else {
                prev->next = curr->next;
            }
            res->wait_count--;
            free_wait_entry(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

/**
 * Get process info structure
 */
static pi_process_info_t *get_process_info(pid32 pid)
{
    if (pid < 0 || pid >= PI_MAX_PROCESSES) {
        return NULL;
    }
    
    if (!processes[pid].active) {
        return NULL;
    }
    
    return &processes[pid];
}

/**
 * Get resource structure
 */
static pi_resource_t *get_resource(int32_t id)
{
    if (id < 0 || id >= PI_MAX_RESOURCES) {
        return NULL;
    }
    
    if (!resources[id].initialized) {
        return NULL;
    }
    
    return &resources[id];
}

/**
 * Get maximum priority of processes waiting on resource
 */
static uint32_t get_max_waiting_priority(pi_resource_t *res)
{
    if (res == NULL || res->wait_queue == NULL) {
        return 0;
    }
    
    /* Queue is sorted by priority descending, so head has max */
    return res->wait_queue->priority;
}

/**
 * Add resource to process's held list
 */
static void add_held_resource(pid32 pid, int32_t resource_id)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return;
    }
    
    if (proc->held_count >= PI_MAX_HELD_RESOURCES) {
        return;
    }
    
    proc->held_resources[proc->held_count++] = resource_id;
}

/**
 * Remove resource from process's held list
 */
static void remove_held_resource(pid32 pid, int32_t resource_id)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return;
    }
    
    for (uint32_t i = 0; i < proc->held_count; i++) {
        if (proc->held_resources[i] == resource_id) {
            /* Shift remaining entries */
            for (uint32_t j = i; j < proc->held_count - 1; j++) {
                proc->held_resources[j] = proc->held_resources[j + 1];
            }
            proc->held_count--;
            return;
        }
    }
}

/**
 * Propagate priority through inheritance chain
 * 
 * When a high-priority process blocks on a resource, we need to
 * propagate its priority to the holder, and transitively to any
 * process that holder is blocked on.
 */
static void propagate_priority(pid32 pid)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return;
    }
    
    /* Get what we're waiting for */
    int32_t waiting_for = proc->waiting_for;
    if (waiting_for == PI_INVALID_RESOURCE) {
        return;
    }
    
    pi_resource_t *res = get_resource(waiting_for);
    if (res == NULL || res->owner == PI_INVALID_PID) {
        return;
    }
    
    /* Get the owner */
    pi_process_info_t *owner = get_process_info(res->owner);
    if (owner == NULL) {
        return;
    }
    
    /* Check if we need to boost owner's priority */
    uint32_t our_priority = proc->current_priority;
    
    if (our_priority > owner->current_priority) {
        /* Inherit our priority */
        owner->inherited_priority = our_priority;
        owner->current_priority = our_priority;
        owner->inheritance_received++;
        
        system_state.total_inheritance_events++;
        res->inheritance_count++;
        
        if (system_state.debug_enabled) {
            kprintf("PI: Process %d inherits priority %u from %d\n",
                    owner->pid, our_priority, pid);
        }
        
        /* Update actual process priority */
        proctab[owner->pid].pprio = our_priority;
        
        /* Propagate further if owner is also waiting */
        if (owner->waiting_for != PI_INVALID_RESOURCE) {
            propagate_priority(owner->pid);
        }
    }
}

/**
 * Recalculate process's effective priority
 * 
 * Called when releasing a resource to determine if priority
 * should be lowered.
 */
static void recalculate_priority(pid32 pid)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return;
    }
    
    /* Start with base priority */
    uint32_t max_priority = proc->base_priority;
    
    /* Check all held resources for waiting processes */
    for (uint32_t i = 0; i < proc->held_count; i++) {
        pi_resource_t *res = get_resource(proc->held_resources[i]);
        if (res != NULL) {
            uint32_t waiting_max = get_max_waiting_priority(res);
            if (waiting_max > max_priority) {
                max_priority = waiting_max;
            }
        }
    }
    
    /* Update priorities */
    proc->inherited_priority = (max_priority > proc->base_priority) ?
                               max_priority : 0;
    proc->current_priority = max_priority;
    
    /* Update actual process priority */
    proctab[pid].pprio = max_priority;
    
    if (system_state.debug_enabled && max_priority != proc->base_priority) {
        kprintf("PI: Process %d priority recalculated to %u (base %u)\n",
                pid, max_priority, proc->base_priority);
    }
}

/**
 * Detect cycle in wait-for graph
 */
static bool detect_cycle(pid32 start_pid, int32_t target_resource)
{
    if (!system_state.deadlock_detection) {
        return false;
    }
    
    pi_resource_t *res = get_resource(target_resource);
    if (res == NULL || res->owner == PI_INVALID_PID) {
        return false;
    }
    
    /* Follow the chain of waiting */
    pid32 current = res->owner;
    int depth = 0;
    
    while (current != PI_INVALID_PID && depth < PI_MAX_NESTING_DEPTH) {
        if (current == start_pid) {
            /* Cycle detected! */
            system_state.deadlocks_detected++;
            return true;
        }
        
        pi_process_info_t *proc = get_process_info(current);
        if (proc == NULL || proc->waiting_for == PI_INVALID_RESOURCE) {
            break;
        }
        
        pi_resource_t *next_res = get_resource(proc->waiting_for);
        if (next_res == NULL) {
            break;
        }
        
        current = next_res->owner;
        depth++;
    }
    
    return false;
}

/**
 * Initialize priority inheritance system
 */
pi_error_t pi_init(pi_protocol_t protocol)
{
    /* Initialize wait entry pool */
    free_wait_entries = NULL;
    for (int i = WAIT_POOL_SIZE - 1; i >= 0; i--) {
        wait_pool[i].next = free_wait_entries;
        free_wait_entries = &wait_pool[i];
    }
    
    /* Initialize resources */
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        memset(&resources[i], 0, sizeof(pi_resource_t));
        resources[i].id = i;
        resources[i].owner = PI_INVALID_PID;
        resources[i].initialized = false;
    }
    
    /* Initialize process info */
    for (int i = 0; i < PI_MAX_PROCESSES; i++) {
        memset(&processes[i], 0, sizeof(pi_process_info_t));
        processes[i].pid = i;
        processes[i].waiting_for = PI_INVALID_RESOURCE;
        processes[i].active = false;
        
        for (int j = 0; j < PI_MAX_HELD_RESOURCES; j++) {
            processes[i].held_resources[j] = PI_INVALID_RESOURCE;
        }
    }
    
    /* Initialize system state */
    memset(&system_state, 0, sizeof(system_state));
    system_state.initialized = true;
    system_state.default_protocol = protocol;
    system_state.deadlock_detection = true;
    system_state.statistics_enabled = true;
    system_state.debug_enabled = false;
    
    return PI_OK;
}

/**
 * Shutdown system
 */
void pi_shutdown(void)
{
    system_state.initialized = false;
}

/**
 * Set default protocol
 */
void pi_set_default_protocol(pi_protocol_t protocol)
{
    system_state.default_protocol = protocol;
}

/**
 * Get default protocol
 */
pi_protocol_t pi_get_default_protocol(void)
{
    return system_state.default_protocol;
}

/**
 * Initialize a resource
 */
pi_error_t pi_resource_init(int32_t id, pi_resource_type_t type,
                            pi_protocol_t protocol, int32_t initial_count,
                            uint32_t ceiling, const char *name)
{
    if (!system_state.initialized) {
        return PI_ERROR_NOT_INITIALIZED;
    }
    
    if (id < 0 || id >= PI_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pi_resource_t *res = &resources[id];
    
    res->id = id;
    res->type = type;
    res->protocol = protocol;
    res->count = initial_count;
    res->max_count = initial_count;
    res->owner = PI_INVALID_PID;
    res->lock_count = 0;
    res->ceiling = ceiling;
    res->computed_ceiling = ceiling;
    res->wait_queue = NULL;
    res->wait_count = 0;
    res->acquisitions = 0;
    res->contentions = 0;
    res->total_hold_time = 0;
    res->max_hold_time = 0;
    res->inheritance_count = 0;
    res->blocking_time = 0;
    res->acquire_time = 0;
    res->name = name;
    res->initialized = true;
    
    return PI_OK;
}

/**
 * Destroy a resource
 */
pi_error_t pi_resource_destroy(int32_t id)
{
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    /* Free wait queue entries */
    while (res->wait_queue != NULL) {
        pi_wait_entry_t *entry = remove_wait_queue_head(res);
        free_wait_entry(entry);
    }
    
    res->initialized = false;
    return PI_OK;
}

/**
 * Set resource ceiling
 */
pi_error_t pi_resource_set_ceiling(int32_t id, uint32_t ceiling)
{
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    if (ceiling > PI_PRIORITY_MAX) {
        ceiling = PI_PRIORITY_MAX;
    }
    
    res->ceiling = ceiling;
    return PI_OK;
}

/**
 * Get resource ceiling
 */
uint32_t pi_resource_get_ceiling(int32_t id)
{
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        return 0;
    }
    return res->ceiling;
}

/**
 * Register process as potential accessor
 */
pi_error_t pi_resource_register_accessor(int32_t resource_id, pid32 pid)
{
    pi_resource_t *res = get_resource(resource_id);
    pi_process_info_t *proc = get_process_info(pid);
    
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    if (proc == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    /* Update computed ceiling if this process has higher priority */
    if (proc->base_priority > res->computed_ceiling) {
        res->computed_ceiling = proc->base_priority;
    }
    
    return PI_OK;
}

/**
 * Acquire a resource using priority inheritance
 */
pi_error_t pi_acquire(int32_t id)
{
    intmask mask;
    pi_error_t result = PI_OK;
    
    if (!system_state.initialized) {
        return PI_ERROR_NOT_INITIALIZED;
    }
    
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    pi_process_info_t *proc = get_process_info(current);
    if (proc == NULL) {
        /* Auto-register process */
        pi_register_process(current, proctab[current].pprio);
        proc = get_process_info(current);
        if (proc == NULL) {
            return PI_ERROR_INVALID_PROCESS;
        }
    }
    
    mask = disable();
    
    /* Check for recursive locking */
    if (res->owner == current) {
        if (res->type == PI_RESOURCE_MUTEX) {
            res->lock_count++;
            restore(mask);
            return PI_OK;
        }
    }
    
    /* Check deadlock */
    if (detect_cycle(current, id)) {
        restore(mask);
        return PI_ERROR_DEADLOCK;
    }
    
    if (res->count > 0) {
        /* Resource available */
        res->count--;
        res->owner = current;
        res->lock_count = 1;
        res->acquire_time = system_state.system_time;
        res->acquisitions++;
        
        add_held_resource(current, id);
        
        if (system_state.debug_enabled) {
            kprintf("PI: Process %d acquired resource %d (%s)\n",
                    current, id, res->name ? res->name : "unnamed");
        }
    } else {
        /* Resource not available - must block */
        res->contentions++;
        system_state.total_inversions_prevented++;
        
        /* Create wait entry */
        pi_wait_entry_t *entry = alloc_wait_entry();
        if (entry == NULL) {
            restore(mask);
            return PI_ERROR_NO_MEMORY;
        }
        
        entry->pid = current;
        entry->priority = proc->current_priority;
        entry->wait_start = system_state.system_time;
        
        /* Add to wait queue */
        insert_wait_queue(res, entry);
        
        /* Mark as waiting */
        proc->waiting_for = id;
        
        /* Propagate priority to holder */
        propagate_priority(current);
        
        /* Block process */
        proctab[current].pstate = PR_WAIT;
        
        if (system_state.debug_enabled) {
            kprintf("PI: Process %d blocking on resource %d (owner %d)\n",
                    current, id, res->owner);
        }
        
        /* Reschedule */
        resched();
        
        /* Woken up - we now have the resource */
        proc->waiting_for = PI_INVALID_RESOURCE;
        
        /* Update blocking time statistics */
        uint64_t blocked_time = system_state.system_time - entry->wait_start;
        proc->total_blocked_time += blocked_time;
        res->blocking_time += blocked_time;
    }
    
    restore(mask);
    return result;
}

/**
 * Try to acquire without blocking
 */
pi_error_t pi_try_acquire(int32_t id)
{
    intmask mask;
    
    if (!system_state.initialized) {
        return PI_ERROR_NOT_INITIALIZED;
    }
    
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    pi_process_info_t *proc = get_process_info(current);
    if (proc == NULL) {
        pi_register_process(current, proctab[current].pprio);
        proc = get_process_info(current);
    }
    
    mask = disable();
    
    /* Check for recursive lock */
    if (res->owner == current && res->type == PI_RESOURCE_MUTEX) {
        res->lock_count++;
        restore(mask);
        return PI_OK;
    }
    
    if (res->count > 0) {
        /* Available */
        res->count--;
        res->owner = current;
        res->lock_count = 1;
        res->acquire_time = system_state.system_time;
        res->acquisitions++;
        add_held_resource(current, id);
        
        restore(mask);
        return PI_OK;
    }
    
    restore(mask);
    return PI_ERROR_RESOURCE_BUSY;
}

/**
 * Acquire with timeout
 */
pi_error_t pi_acquire_timeout(int32_t id, uint32_t timeout)
{
    /* For simplicity, implement as polling with yield */
    uint64_t deadline = system_state.system_time + timeout;
    
    while (system_state.system_time < deadline) {
        pi_error_t result = pi_try_acquire(id);
        if (result == PI_OK) {
            return PI_OK;
        }
        
        /* Yield and try again */
        resched();
    }
    
    return PI_ERROR_RESOURCE_BUSY;
}

/**
 * Release a resource
 */
pi_error_t pi_release(int32_t id)
{
    intmask mask;
    
    if (!system_state.initialized) {
        return PI_ERROR_NOT_INITIALIZED;
    }
    
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    
    mask = disable();
    
    /* Verify ownership */
    if (res->owner != current) {
        restore(mask);
        return PI_ERROR_NOT_OWNER;
    }
    
    /* Handle recursive lock */
    if (res->lock_count > 1) {
        res->lock_count--;
        restore(mask);
        return PI_OK;
    }
    
    /* Update hold time statistics */
    uint64_t hold_time = system_state.system_time - res->acquire_time;
    res->total_hold_time += hold_time;
    if (hold_time > res->max_hold_time) {
        res->max_hold_time = hold_time;
    }
    
    /* Remove from our held list */
    remove_held_resource(current, id);
    
    if (system_state.debug_enabled) {
        kprintf("PI: Process %d releasing resource %d (%s)\n",
                current, id, res->name ? res->name : "unnamed");
    }
    
    /* Check if anyone is waiting */
    if (res->wait_queue != NULL) {
        /* Wake highest priority waiter */
        pi_wait_entry_t *entry = remove_wait_queue_head(res);
        pid32 next_owner = entry->pid;
        
        /* Transfer ownership */
        res->owner = next_owner;
        res->lock_count = 1;
        res->acquire_time = system_state.system_time;
        res->acquisitions++;
        
        add_held_resource(next_owner, id);
        
        /* Update next owner's waiting state */
        pi_process_info_t *next_proc = get_process_info(next_owner);
        if (next_proc != NULL) {
            next_proc->waiting_for = PI_INVALID_RESOURCE;
        }
        
        /* Wake up the process */
        proctab[next_owner].pstate = PR_READY;
        ready(next_owner, RESCHED_NO);
        
        free_wait_entry(entry);
        
        if (system_state.debug_enabled) {
            kprintf("PI: Resource %d transferred to process %d\n", id, next_owner);
        }
    } else {
        /* No waiters */
        res->count++;
        res->owner = PI_INVALID_PID;
        res->lock_count = 0;
    }
    
    /* Recalculate our priority */
    recalculate_priority(current);
    
    /* Reschedule in case we lowered our priority */
    resched();
    
    restore(mask);
    return PI_OK;
}

/**
 * Register a process
 */
pi_error_t pi_register_process(pid32 pid, uint32_t priority)
{
    if (pid < 0 || pid >= PI_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    pi_process_info_t *proc = &processes[pid];
    
    proc->pid = pid;
    proc->base_priority = priority;
    proc->current_priority = priority;
    proc->inherited_priority = 0;
    proc->held_count = 0;
    proc->waiting_for = PI_INVALID_RESOURCE;
    proc->priority_stack_top = 0;
    proc->total_blocked_time = 0;
    proc->inheritance_received = 0;
    proc->blocking_caused = 0;
    proc->active = true;
    
    for (int i = 0; i < PI_MAX_HELD_RESOURCES; i++) {
        proc->held_resources[i] = PI_INVALID_RESOURCE;
    }
    
    return PI_OK;
}

/**
 * Unregister a process
 */
pi_error_t pi_unregister_process(pid32 pid)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    /* Release any held resources */
    while (proc->held_count > 0) {
        pi_release(proc->held_resources[0]);
    }
    
    proc->active = false;
    return PI_OK;
}

/**
 * Set base priority
 */
pi_error_t pi_set_base_priority(pid32 pid, uint32_t priority)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    proc->base_priority = priority;
    recalculate_priority(pid);
    
    return PI_OK;
}

/**
 * Get effective priority
 */
uint32_t pi_get_effective_priority(pid32 pid)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return 0;
    }
    return proc->current_priority;
}

/**
 * Get base priority
 */
uint32_t pi_get_base_priority(pid32 pid)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        return 0;
    }
    return proc->base_priority;
}

/**
 * Enable/disable deadlock detection
 */
void pi_deadlock_detection_enable(bool enable)
{
    system_state.deadlock_detection = enable;
}

/**
 * Check for deadlock
 */
bool pi_check_deadlock(pid32 pid, int32_t resource_id)
{
    return detect_cycle(pid, resource_id);
}

/**
 * Get deadlock chain
 */
bool pi_get_deadlock_chain(pi_inheritance_chain_t *chain)
{
    if (chain == NULL) {
        return false;
    }
    
    /* Find a process that's in a cycle */
    for (int i = 0; i < PI_MAX_PROCESSES; i++) {
        if (processes[i].active && processes[i].waiting_for != PI_INVALID_RESOURCE) {
            if (detect_cycle(i, processes[i].waiting_for)) {
                pi_get_inheritance_chain(i, chain);
                return true;
            }
        }
    }
    
    chain->length = 0;
    return false;
}

/**
 * Timer tick
 */
void pi_tick(void)
{
    system_state.system_time++;
}

/**
 * Get system time
 */
uint64_t pi_get_time(void)
{
    return system_state.system_time;
}

/**
 * Get statistics
 */
void pi_get_stats(pi_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }
    
    stats->inversions_prevented = system_state.total_inversions_prevented;
    stats->inheritance_events = system_state.total_inheritance_events;
    stats->ceiling_raises = system_state.total_ceiling_raises;
    stats->deadlocks_detected = system_state.deadlocks_detected;
    
    /* Calculate total blocking time */
    stats->total_blocking_time = 0;
    stats->max_blocking_time = 0;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        if (resources[i].initialized) {
            stats->total_blocking_time += resources[i].blocking_time;
            if (resources[i].max_hold_time > stats->max_blocking_time) {
                stats->max_blocking_time = resources[i].max_hold_time;
            }
        }
    }
    
    /* Calculate average and rate */
    uint64_t total_acquisitions = 0;
    uint64_t total_contentions = 0;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        if (resources[i].initialized) {
            total_acquisitions += resources[i].acquisitions;
            total_contentions += resources[i].contentions;
        }
    }
    
    stats->avg_blocking_time = (total_contentions > 0) ?
        stats->total_blocking_time / total_contentions : 0;
    
    stats->inversion_rate = (total_acquisitions > 0) ?
        (double)total_contentions / total_acquisitions : 0.0;
    
    stats->max_chain_length = 0;  /* Would need to track this */
}

/**
 * Reset statistics
 */
void pi_reset_stats(void)
{
    system_state.total_inversions_prevented = 0;
    system_state.total_inheritance_events = 0;
    system_state.total_ceiling_raises = 0;
    system_state.deadlocks_detected = 0;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        if (resources[i].initialized) {
            resources[i].acquisitions = 0;
            resources[i].contentions = 0;
            resources[i].total_hold_time = 0;
            resources[i].max_hold_time = 0;
            resources[i].inheritance_count = 0;
            resources[i].blocking_time = 0;
        }
    }
    
    for (int i = 0; i < PI_MAX_PROCESSES; i++) {
        if (processes[i].active) {
            processes[i].total_blocked_time = 0;
            processes[i].inheritance_received = 0;
            processes[i].blocking_caused = 0;
        }
    }
}

/**
 * Print statistics
 */
void pi_print_stats(void)
{
    pi_stats_t stats;
    pi_get_stats(&stats);
    
    kprintf("\n=== Priority Inheritance Statistics ===\n");
    kprintf("Protocol: Priority Inheritance\n");
    kprintf("System time: %llu ticks\n", system_state.system_time);
    kprintf("\n");
    kprintf("Inversions prevented: %llu\n", stats.inversions_prevented);
    kprintf("Inheritance events: %llu\n", stats.inheritance_events);
    kprintf("Deadlocks detected: %llu\n", stats.deadlocks_detected);
    kprintf("\n");
    kprintf("Total blocking time: %llu ticks\n", stats.total_blocking_time);
    kprintf("Max blocking time: %llu ticks\n", stats.max_blocking_time);
    kprintf("Avg blocking time: %llu ticks\n", stats.avg_blocking_time);
    kprintf("Inversion rate: %.2f%%\n", stats.inversion_rate * 100);
}

/**
 * Get resource statistics
 */
void pi_get_resource_stats(int32_t id, uint64_t *acquisitions,
                           uint64_t *contentions, uint64_t *avg_hold)
{
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        if (acquisitions) *acquisitions = 0;
        if (contentions) *contentions = 0;
        if (avg_hold) *avg_hold = 0;
        return;
    }
    
    if (acquisitions) *acquisitions = res->acquisitions;
    if (contentions) *contentions = res->contentions;
    if (avg_hold) {
        *avg_hold = (res->acquisitions > 0) ?
            res->total_hold_time / res->acquisitions : 0;
    }
}

/**
 * Enable debug output
 */
void pi_debug_enable(bool enable)
{
    system_state.debug_enabled = enable;
}

/**
 * Print resource state
 */
void pi_print_resource(int32_t id)
{
    pi_resource_t *res = get_resource(id);
    if (res == NULL) {
        kprintf("Resource %d: not initialized\n", id);
        return;
    }
    
    const char *type_names[] = {"MUTEX", "SEMAPHORE", "RWLOCK"};
    const char *proto_names[] = {"NONE", "INHERITANCE", "CEILING", "IMMED_CEIL", "SRP"};
    
    kprintf("\nResource %d (%s):\n", id, res->name ? res->name : "unnamed");
    kprintf("  Type: %s, Protocol: %s\n", type_names[res->type], proto_names[res->protocol]);
    kprintf("  Count: %d/%d, Owner: %d, Lock count: %u\n",
            res->count, res->max_count, res->owner, res->lock_count);
    kprintf("  Ceiling: %u (computed: %u)\n", res->ceiling, res->computed_ceiling);
    kprintf("  Wait queue (%u waiters):\n", res->wait_count);
    
    pi_wait_entry_t *entry = res->wait_queue;
    while (entry != NULL) {
        kprintf("    PID %d (prio %u, waiting since %llu)\n",
                entry->pid, entry->priority, entry->wait_start);
        entry = entry->next;
    }
    
    kprintf("  Statistics:\n");
    kprintf("    Acquisitions: %llu, Contentions: %llu\n",
            res->acquisitions, res->contentions);
    kprintf("    Inheritance events: %llu\n", res->inheritance_count);
    kprintf("    Total hold time: %llu, Max: %llu\n",
            res->total_hold_time, res->max_hold_time);
}

/**
 * Print all resources
 */
void pi_print_all_resources(void)
{
    kprintf("\n=== All Resources ===\n");
    
    int count = 0;
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        if (resources[i].initialized) {
            pi_print_resource(i);
            count++;
        }
    }
    
    kprintf("\nTotal initialized resources: %d\n", count);
}

/**
 * Print process state
 */
void pi_print_process(pid32 pid)
{
    pi_process_info_t *proc = get_process_info(pid);
    if (proc == NULL) {
        kprintf("Process %d: not registered\n", pid);
        return;
    }
    
    kprintf("\nProcess %d:\n", pid);
    kprintf("  Base priority: %u\n", proc->base_priority);
    kprintf("  Current priority: %u\n", proc->current_priority);
    kprintf("  Inherited priority: %u\n", proc->inherited_priority);
    kprintf("  Waiting for: %d\n", proc->waiting_for);
    kprintf("  Held resources (%u):", proc->held_count);
    
    for (uint32_t i = 0; i < proc->held_count; i++) {
        kprintf(" %d", proc->held_resources[i]);
    }
    kprintf("\n");
    
    kprintf("  Statistics:\n");
    kprintf("    Total blocked time: %llu\n", proc->total_blocked_time);
    kprintf("    Inheritance received: %llu\n", proc->inheritance_received);
}

/**
 * Print inheritance chain
 */
void pi_print_chain(pi_inheritance_chain_t *chain)
{
    if (chain == NULL || chain->length == 0) {
        kprintf("Empty inheritance chain\n");
        return;
    }
    
    kprintf("Inheritance chain (length %u):\n", chain->length);
    
    for (uint32_t i = 0; i < chain->length; i++) {
        kprintf("  [%u] PID %d (prio %u) -> Resource %d\n",
                i, chain->chain[i], chain->priorities[i], chain->resources[i]);
    }
}

/**
 * Validate system state
 */
bool pi_validate(void)
{
    bool valid = true;
    
    /* Check all resources */
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        pi_resource_t *res = &resources[i];
        if (!res->initialized) continue;
        
        /* If has owner, owner should have this in held list */
        if (res->owner != PI_INVALID_PID) {
            pi_process_info_t *owner = get_process_info(res->owner);
            if (owner == NULL) {
                kprintf("Validate: Resource %d has invalid owner %d\n", i, res->owner);
                valid = false;
            } else {
                bool found = false;
                for (uint32_t j = 0; j < owner->held_count; j++) {
                    if (owner->held_resources[j] == i) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    kprintf("Validate: Resource %d not in owner %d's held list\n",
                            i, res->owner);
                    valid = false;
                }
            }
        }
        
        /* Verify wait count matches queue length */
        uint32_t counted = 0;
        pi_wait_entry_t *entry = res->wait_queue;
        while (entry != NULL) {
            counted++;
            entry = entry->next;
        }
        if (counted != res->wait_count) {
            kprintf("Validate: Resource %d wait_count mismatch (%u vs %u)\n",
                    i, res->wait_count, counted);
            valid = false;
        }
    }
    
    /* Check all processes */
    for (int i = 0; i < PI_MAX_PROCESSES; i++) {
        pi_process_info_t *proc = &processes[i];
        if (!proc->active) continue;
        
        /* If waiting, should be in that resource's queue */
        if (proc->waiting_for != PI_INVALID_RESOURCE) {
            pi_resource_t *res = get_resource(proc->waiting_for);
            if (res == NULL) {
                kprintf("Validate: Process %d waiting for invalid resource %d\n",
                        i, proc->waiting_for);
                valid = false;
            } else {
                bool found = false;
                pi_wait_entry_t *entry = res->wait_queue;
                while (entry != NULL) {
                    if (entry->pid == i) {
                        found = true;
                        break;
                    }
                    entry = entry->next;
                }
                if (!found) {
                    kprintf("Validate: Process %d not in resource %d's wait queue\n",
                            i, proc->waiting_for);
                    valid = false;
                }
            }
        }
        
        /* Current priority should be >= base priority */
        if (proc->current_priority < proc->base_priority) {
            kprintf("Validate: Process %d current prio %u < base %u\n",
                    i, proc->current_priority, proc->base_priority);
            valid = false;
        }
    }
    
    return valid;
}

/**
 * Get inheritance chain from a process
 */
uint32_t pi_get_inheritance_chain(pid32 pid, pi_inheritance_chain_t *chain)
{
    if (chain == NULL) {
        return 0;
    }
    
    chain->length = 0;
    
    pid32 current = pid;
    
    while (current != PI_INVALID_PID && chain->length < PI_MAX_NESTING_DEPTH) {
        pi_process_info_t *proc = get_process_info(current);
        if (proc == NULL) {
            break;
        }
        
        chain->chain[chain->length] = current;
        chain->priorities[chain->length] = proc->current_priority;
        chain->resources[chain->length] = proc->waiting_for;
        chain->length++;
        
        if (proc->waiting_for == PI_INVALID_RESOURCE) {
            break;
        }
        
        pi_resource_t *res = get_resource(proc->waiting_for);
        if (res == NULL) {
            break;
        }
        
        current = res->owner;
    }
    
    return chain->length;
}
