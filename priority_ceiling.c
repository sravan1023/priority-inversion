/*
 * priority_ceiling.c - Priority Ceiling Protocol Implementation
 *
 * Implements multiple ceiling-based protocols:
 * 
 * 1. Original Priority Ceiling Protocol (OPCP):
 *    - Each resource has a ceiling equal to highest priority of any accessor
 *    - A process can only lock if its priority > system ceiling
 *    - Prevents deadlock and provides bounded blocking
 *
 * 2. Immediate Priority Ceiling Protocol (IPCP):
 *    - Process immediately inherits ceiling when locking
 *    - Simpler than OPCP, same deadlock prevention
 *    - Also known as Priority Ceiling Emulation
 *
 * 3. Stack Resource Policy (SRP):
 *    - Uses preemption levels instead of priorities
 *    - Single blocking per preemption level
 *    - Works well with EDF scheduling
 */

#include "priority_inversion.h"
#include "../include/kernel.h"
#include "../include/process.h"
#include "../include/interrupts.h"
#include <string.h>


// Which ceiling protocol variant to use //
typedef enum ceiling_variant {
    CEILING_ORIGINAL,           // Original PCP //
    CEILING_IMMEDIATE,          // Immediate PCP //
    CEILING_SRP,                // Stack Resource Policy //
} ceiling_variant_t;

// Default variant //
static ceiling_variant_t active_variant = CEILING_IMMEDIATE;


/* Ceiling resource structure */
typedef struct pc_resource {
    int32_t             id;
    bool                initialized;
    const char          *name;
    
    /* State */
    int32_t             count;
    int32_t             max_count;
    pid32               owner;
    uint32_t            lock_count;
    
    /* Ceiling priorities */
    uint32_t            ceiling;            /* Static ceiling */
    uint32_t            computed_ceiling;   /* Computed from accessors */
    
    /* Accessor tracking for ceiling computation */
    pid32               accessors[PI_MAX_PROCESSES];
    uint32_t            accessor_count;
    
    /* Wait queue (FIFO for ceiling protocol) */
    pid32               wait_queue[PI_MAX_PROCESSES];
    uint32_t            wait_head;
    uint32_t            wait_tail;
    uint32_t            wait_count;
    
    /* SRP specific */
    uint32_t            preemption_level;
    
    /* Statistics */
    uint64_t            acquisitions;
    uint64_t            contentions;
    uint64_t            ceiling_raises;
    uint64_t            total_hold_time;
    uint64_t            max_hold_time;
    uint64_t            blocking_time;
    uint64_t            acquire_time;
} pc_resource_t;

/* Process ceiling state */
typedef struct pc_process {
    pid32               pid;
    bool                active;
    
    /* Priority tracking */
    uint32_t            base_priority;
    uint32_t            current_priority;
    
    /* Priority stack for nested locking */
    uint32_t            priority_stack[PI_MAX_NESTING_DEPTH];
    uint32_t            stack_top;
    
    /* Held resources */
    int32_t             held_resources[PI_MAX_HELD_RESOURCES];
    uint32_t            held_count;
    
    /* SRP preemption level */
    uint32_t            preemption_level;
    
    /* Statistics */
    uint64_t            total_blocked_time;
    uint64_t            ceiling_raises;
} pc_process_t;

/* System state */
typedef struct pc_system {
    bool                initialized;
    uint64_t            system_time;
    
    /* System ceiling (for OPCP) */
    uint32_t            system_ceiling;
    
    /* System preemption level (for SRP) */
    uint32_t            system_preemption_level;
    
    /* Currently running process */
    pid32               current_pid;
    
    /* Statistics */
    uint64_t            total_ceiling_raises;
    uint64_t            total_blockings;
    uint64_t            deadlocks_prevented;
    
    bool                debug_enabled;
} pc_system_t;

/* Global data */
static pc_resource_t pc_resources[PI_MAX_RESOURCES];
static pc_process_t pc_processes[PI_MAX_PROCESSES];
static pc_system_t pc_system;


static pc_resource_t *get_pc_resource(int32_t id);
static pc_process_t *get_pc_process(pid32 pid);
static void update_system_ceiling(void);
static uint32_t get_highest_ceiling_held(pid32 pid);
static void push_priority(pc_process_t *proc, uint32_t priority);
static uint32_t pop_priority(pc_process_t *proc);
static void enqueue_waiter(pc_resource_t *res, pid32 pid);
static pid32 dequeue_waiter(pc_resource_t *res);
static bool can_acquire_opcp(pc_process_t *proc, pc_resource_t *res);
static void add_pc_held(pc_process_t *proc, int32_t id);
static void remove_pc_held(pc_process_t *proc, int32_t id);


static pc_resource_t *get_pc_resource(int32_t id)
{
    if (id < 0 || id >= PI_MAX_RESOURCES) {
        return NULL;
    }
    if (!pc_resources[id].initialized) {
        return NULL;
    }
    return &pc_resources[id];
}

static pc_process_t *get_pc_process(pid32 pid)
{
    if (pid < 0 || pid >= PI_MAX_PROCESSES) {
        return NULL;
    }
    if (!pc_processes[pid].active) {
        return NULL;
    }
    return &pc_processes[pid];
}


/**
 * Update system ceiling based on all locked resources
 */
static void update_system_ceiling(void)
{
    uint32_t max_ceiling = 0;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        pc_resource_t *res = &pc_resources[i];
        if (res->initialized && res->owner != PI_INVALID_PID) {
            if (res->ceiling > max_ceiling) {
                max_ceiling = res->ceiling;
            }
        }
    }
    
    pc_system.system_ceiling = max_ceiling;
    
    if (pc_system.debug_enabled) {
        kprintf("PC: System ceiling updated to %u\n", max_ceiling);
    }
}

/**
 * Get highest ceiling of resources held by process
 */
static uint32_t get_highest_ceiling_held(pid32 pid)
{
    pc_process_t *proc = get_pc_process(pid);
    if (proc == NULL) {
        return 0;
    }
    
    uint32_t max_ceiling = 0;
    
    for (uint32_t i = 0; i < proc->held_count; i++) {
        pc_resource_t *res = get_pc_resource(proc->held_resources[i]);
        if (res != NULL && res->ceiling > max_ceiling) {
            max_ceiling = res->ceiling;
        }
    }
    
    return max_ceiling;
}


/**
 * Push priority onto stack
 */
static void push_priority(pc_process_t *proc, uint32_t priority)
{
    if (proc == NULL || proc->stack_top >= PI_MAX_NESTING_DEPTH) {
        return;
    }
    proc->priority_stack[proc->stack_top++] = priority;
}

/**
 * Pop priority from stack
 */
static uint32_t pop_priority(pc_process_t *proc)
{
    if (proc == NULL || proc->stack_top == 0) {
        return 0;
    }
    return proc->priority_stack[--proc->stack_top];
}


/**
 * Add process to wait queue (FIFO)
 */
static void enqueue_waiter(pc_resource_t *res, pid32 pid)
{
    if (res == NULL || res->wait_count >= PI_MAX_PROCESSES) {
        return;
    }
    
    res->wait_queue[res->wait_tail] = pid;
    res->wait_tail = (res->wait_tail + 1) % PI_MAX_PROCESSES;
    res->wait_count++;
}

/**
 * Remove process from wait queue
 */
static pid32 dequeue_waiter(pc_resource_t *res)
{
    if (res == NULL || res->wait_count == 0) {
        return PI_INVALID_PID;
    }
    
    pid32 pid = res->wait_queue[res->wait_head];
    res->wait_head = (res->wait_head + 1) % PI_MAX_PROCESSES;
    res->wait_count--;
    
    return pid;
}


static void add_pc_held(pc_process_t *proc, int32_t id)
{
    if (proc == NULL || proc->held_count >= PI_MAX_HELD_RESOURCES) {
        return;
    }
    proc->held_resources[proc->held_count++] = id;
}

static void remove_pc_held(pc_process_t *proc, int32_t id)
{
    if (proc == NULL) {
        return;
    }
    
    for (uint32_t i = 0; i < proc->held_count; i++) {
        if (proc->held_resources[i] == id) {
            for (uint32_t j = i; j < proc->held_count - 1; j++) {
                proc->held_resources[j] = proc->held_resources[j + 1];
            }
            proc->held_count--;
            return;
        }
    }
}


/**
 * Check if process can acquire resource under OPCP
 */
static bool can_acquire_opcp(pc_process_t *proc, pc_resource_t *res)
{
    if (proc == NULL || res == NULL) {
        return false;
    }
    
    /* Can always acquire free resource */
    if (res->owner == PI_INVALID_PID) {
        return true;
    }
    
    /* Already own it (recursive) */
    if (res->owner == proc->pid) {
        return true;
    }
    
    /* Check against system ceiling */
    /* Can acquire if priority > system ceiling OR we hold the blocking resource */
    if (proc->current_priority > pc_system.system_ceiling) {
        return true;
    }
    
    /* Check if we own a resource with the system ceiling */
    for (uint32_t i = 0; i < proc->held_count; i++) {
        pc_resource_t *held = get_pc_resource(proc->held_resources[i]);
        if (held != NULL && held->ceiling == pc_system.system_ceiling) {
            return true;
        }
    }
    
    return false;
}


/**
 * Initialize ceiling protocol system
 */
void pc_init(ceiling_variant_t variant)
{
    active_variant = variant;
    
    /* Initialize resources */
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        memset(&pc_resources[i], 0, sizeof(pc_resource_t));
        pc_resources[i].id = i;
        pc_resources[i].owner = PI_INVALID_PID;
        pc_resources[i].initialized = false;
    }
    
    /* Initialize processes */
    for (int i = 0; i < PI_MAX_PROCESSES; i++) {
        memset(&pc_processes[i], 0, sizeof(pc_process_t));
        pc_processes[i].pid = i;
        pc_processes[i].active = false;
    }
    
    /* Initialize system */
    memset(&pc_system, 0, sizeof(pc_system_t));
    pc_system.initialized = true;
    pc_system.current_pid = PI_INVALID_PID;
}

/**
 * Shutdown ceiling protocol
 */
void pc_shutdown(void)
{
    pc_system.initialized = false;
}

/**
 * Set active variant
 */
void pc_set_variant(ceiling_variant_t variant)
{
    active_variant = variant;
}


/**
 * Initialize a ceiling-protected resource
 */
pi_error_t pc_resource_init(int32_t id, int32_t initial_count,
                            uint32_t ceiling, const char *name)
{
    if (id < 0 || id >= PI_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pc_resource_t *res = &pc_resources[id];
    
    res->id = id;
    res->name = name;
    res->count = initial_count;
    res->max_count = initial_count;
    res->owner = PI_INVALID_PID;
    res->lock_count = 0;
    res->ceiling = ceiling;
    res->computed_ceiling = ceiling;
    res->accessor_count = 0;
    res->wait_head = 0;
    res->wait_tail = 0;
    res->wait_count = 0;
    res->preemption_level = ceiling;  /* For SRP */
    res->acquisitions = 0;
    res->contentions = 0;
    res->ceiling_raises = 0;
    res->total_hold_time = 0;
    res->max_hold_time = 0;
    res->blocking_time = 0;
    res->initialized = true;
    
    return PI_OK;
}

/**
 * Destroy resource
 */
pi_error_t pc_resource_destroy(int32_t id)
{
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    res->initialized = false;
    return PI_OK;
}

/**
 * Set ceiling priority
 */
pi_error_t pc_set_ceiling(int32_t id, uint32_t ceiling)
{
    pc_resource_t *res = get_pc_resource(id);
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
 * Get ceiling priority
 */
uint32_t pc_get_ceiling(int32_t id)
{
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return 0;
    }
    return res->ceiling;
}

/**
 * Register process as potential accessor (for ceiling computation)
 */
pi_error_t pc_register_accessor(int32_t resource_id, pid32 pid)
{
    pc_resource_t *res = get_pc_resource(resource_id);
    pc_process_t *proc = get_pc_process(pid);
    
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    if (proc == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    /* Add to accessor list */
    if (res->accessor_count < PI_MAX_PROCESSES) {
        res->accessors[res->accessor_count++] = pid;
    }
    
    /* Update computed ceiling */
    if (proc->base_priority > res->computed_ceiling) {
        res->computed_ceiling = proc->base_priority;
        
        /* Update actual ceiling if using computed */
        if (res->ceiling == 0) {
            res->ceiling = res->computed_ceiling;
        }
    }
    
    return PI_OK;
}

/**
 * Compute ceiling from registered accessors
 */
void pc_compute_ceiling(int32_t id)
{
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return;
    }
    
    uint32_t max_prio = 0;
    
    for (uint32_t i = 0; i < res->accessor_count; i++) {
        pc_process_t *proc = get_pc_process(res->accessors[i]);
        if (proc != NULL && proc->base_priority > max_prio) {
            max_prio = proc->base_priority;
        }
    }
    
    res->computed_ceiling = max_prio;
    res->ceiling = max_prio;
}


/**
 * Register process
 */
pi_error_t pc_register_process(pid32 pid, uint32_t priority)
{
    if (pid < 0 || pid >= PI_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    pc_process_t *proc = &pc_processes[pid];
    
    proc->pid = pid;
    proc->base_priority = priority;
    proc->current_priority = priority;
    proc->stack_top = 0;
    proc->held_count = 0;
    proc->preemption_level = priority;  /* For SRP */
    proc->total_blocked_time = 0;
    proc->ceiling_raises = 0;
    proc->active = true;
    
    return PI_OK;
}

/**
 * Unregister process
 */
pi_error_t pc_unregister_process(pid32 pid)
{
    pc_process_t *proc = get_pc_process(pid);
    if (proc == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    /* Release any held resources */
    while (proc->held_count > 0) {
        pc_release(proc->held_resources[0]);
    }
    
    proc->active = false;
    return PI_OK;
}


/**
 * Acquire using IPCP
 */
static pi_error_t ipcp_acquire(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    pc_process_t *proc = get_pc_process(current);
    if (proc == NULL) {
        pc_register_process(current, proctab[current].pprio);
        proc = get_pc_process(current);
    }
    
    mask = disable();
    
    /* Check recursive lock */
    if (res->owner == current) {
        res->lock_count++;
        restore(mask);
        return PI_OK;
    }
    
    if (res->count > 0) {
        /* Resource available */
        res->count--;
        res->owner = current;
        res->lock_count = 1;
        res->acquire_time = pc_system.system_time;
        res->acquisitions++;
        
        add_pc_held(proc, id);
        
        /* IPCP: Immediately raise to ceiling */
        push_priority(proc, proc->current_priority);
        
        if (res->ceiling > proc->current_priority) {
            proc->current_priority = res->ceiling;
            proctab[current].pprio = res->ceiling;
            res->ceiling_raises++;
            proc->ceiling_raises++;
            pc_system.total_ceiling_raises++;
            
            if (pc_system.debug_enabled) {
                kprintf("IPCP: Process %d raised to ceiling %u\n",
                        current, res->ceiling);
            }
        }
        
        update_system_ceiling();
        
    } else {
        /* Must block */
        res->contentions++;
        pc_system.total_blockings++;
        
        /* With IPCP, blocking is bounded because holder has ceiling priority */
        enqueue_waiter(res, current);
        proctab[current].pstate = PR_WAIT;
        
        if (pc_system.debug_enabled) {
            kprintf("IPCP: Process %d blocking on resource %d\n", current, id);
        }
        
        resched();
        
        /* Woken up - now we have the resource */
        /* Priority already raised by release */
    }
    
    restore(mask);
    return PI_OK;
}

/**
 * Release using IPCP
 */
static pi_error_t ipcp_release(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    
    mask = disable();
    
    if (res->owner != current) {
        restore(mask);
        return PI_ERROR_NOT_OWNER;
    }
    
    /* Handle recursive */
    if (res->lock_count > 1) {
        res->lock_count--;
        restore(mask);
        return PI_OK;
    }
    
    /* Update statistics */
    uint64_t hold_time = pc_system.system_time - res->acquire_time;
    res->total_hold_time += hold_time;
    if (hold_time > res->max_hold_time) {
        res->max_hold_time = hold_time;
    }
    
    pc_process_t *proc = get_pc_process(current);
    if (proc != NULL) {
        remove_pc_held(proc, id);
        
        /* Restore previous priority */
        uint32_t old_priority = pop_priority(proc);
        proc->current_priority = old_priority;
        proctab[current].pprio = old_priority;
        
        if (pc_system.debug_enabled) {
            kprintf("IPCP: Process %d priority restored to %u\n",
                    current, old_priority);
        }
    }
    
    /* Check for waiters */
    if (res->wait_count > 0) {
        pid32 next = dequeue_waiter(res);
        pc_process_t *next_proc = get_pc_process(next);
        
        /* Transfer ownership */
        res->owner = next;
        res->lock_count = 1;
        res->acquire_time = pc_system.system_time;
        res->acquisitions++;
        
        if (next_proc != NULL) {
            add_pc_held(next_proc, id);
            
            /* Raise next owner to ceiling */
            push_priority(next_proc, next_proc->current_priority);
            if (res->ceiling > next_proc->current_priority) {
                next_proc->current_priority = res->ceiling;
                proctab[next].pprio = res->ceiling;
                res->ceiling_raises++;
            }
        }
        
        /* Wake up */
        proctab[next].pstate = PR_READY;
        ready(next, RESCHED_NO);
    } else {
        res->count++;
        res->owner = PI_INVALID_PID;
        res->lock_count = 0;
    }
    
    update_system_ceiling();
    resched();
    
    restore(mask);
    return PI_OK;
}


/**
 * Acquire using OPCP
 */
static pi_error_t opcp_acquire(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    pc_process_t *proc = get_pc_process(current);
    if (proc == NULL) {
        pc_register_process(current, proctab[current].pprio);
        proc = get_pc_process(current);
    }
    
    mask = disable();
    
    /* Check recursive */
    if (res->owner == current) {
        res->lock_count++;
        restore(mask);
        return PI_OK;
    }
    
    /* OPCP: Check ceiling condition */
    if (!can_acquire_opcp(proc, res)) {
        /* Cannot acquire - must block */
        res->contentions++;
        pc_system.total_blockings++;
        pc_system.deadlocks_prevented++;  /* Ceiling protocol prevents deadlock */
        
        enqueue_waiter(res, current);
        proctab[current].pstate = PR_WAIT;
        
        if (pc_system.debug_enabled) {
            kprintf("OPCP: Process %d blocked (prio %u <= system ceiling %u)\n",
                    current, proc->current_priority, pc_system.system_ceiling);
        }
        
        resched();
    }
    
    /* Now we can acquire */
    if (res->count > 0) {
        res->count--;
        res->owner = current;
        res->lock_count = 1;
        res->acquire_time = pc_system.system_time;
        res->acquisitions++;
        
        add_pc_held(proc, id);
        
        /* In OPCP, priority inheritance happens when blocking occurs */
        /* (not immediate raise like IPCP) */
        
        update_system_ceiling();
    }
    
    restore(mask);
    return PI_OK;
}

/**
 * Release using OPCP
 */
static pi_error_t opcp_release(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    
    mask = disable();
    
    if (res->owner != current) {
        restore(mask);
        return PI_ERROR_NOT_OWNER;
    }
    
    if (res->lock_count > 1) {
        res->lock_count--;
        restore(mask);
        return PI_OK;
    }
    
    /* Update statistics */
    uint64_t hold_time = pc_system.system_time - res->acquire_time;
    res->total_hold_time += hold_time;
    if (hold_time > res->max_hold_time) {
        res->max_hold_time = hold_time;
    }
    
    pc_process_t *proc = get_pc_process(current);
    if (proc != NULL) {
        remove_pc_held(proc, id);
    }
    
    /* Check for waiters */
    if (res->wait_count > 0) {
        pid32 next = dequeue_waiter(res);
        pc_process_t *next_proc = get_pc_process(next);
        
        res->owner = next;
        res->lock_count = 1;
        res->acquire_time = pc_system.system_time;
        res->acquisitions++;
        
        if (next_proc != NULL) {
            add_pc_held(next_proc, id);
        }
        
        proctab[next].pstate = PR_READY;
        ready(next, RESCHED_NO);
    } else {
        res->count++;
        res->owner = PI_INVALID_PID;
        res->lock_count = 0;
    }
    
    update_system_ceiling();
    resched();
    
    restore(mask);
    return PI_OK;
}


/**
 * Update system preemption level for SRP
 */
static void srp_update_system_level(void)
{
    uint32_t max_level = 0;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        pc_resource_t *res = &pc_resources[i];
        if (res->initialized && res->owner != PI_INVALID_PID) {
            if (res->preemption_level > max_level) {
                max_level = res->preemption_level;
            }
        }
    }
    
    pc_system.system_preemption_level = max_level;
}

/**
 * Acquire using SRP
 */
static pi_error_t srp_acquire(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    pc_process_t *proc = get_pc_process(current);
    if (proc == NULL) {
        pc_register_process(current, proctab[current].pprio);
        proc = get_pc_process(current);
    }
    
    mask = disable();
    
    /* Check recursive */
    if (res->owner == current) {
        res->lock_count++;
        restore(mask);
        return PI_OK;
    }
    
    /* SRP: Check preemption level */
    /* A job can preempt and access resources if its preemption level
       is higher than the system preemption level */
    if (proc->preemption_level <= pc_system.system_preemption_level &&
        res->owner != PI_INVALID_PID) {
        /* Cannot access - block at dispatch time */
        res->contentions++;
        pc_system.total_blockings++;
        
        enqueue_waiter(res, current);
        proctab[current].pstate = PR_WAIT;
        
        if (pc_system.debug_enabled) {
            kprintf("SRP: Process %d blocked (level %u <= system %u)\n",
                    current, proc->preemption_level, pc_system.system_preemption_level);
        }
        
        resched();
    }
    
    /* Acquire */
    if (res->count > 0) {
        res->count--;
        res->owner = current;
        res->lock_count = 1;
        res->acquire_time = pc_system.system_time;
        res->acquisitions++;
        
        add_pc_held(proc, id);
        srp_update_system_level();
    }
    
    restore(mask);
    return PI_OK;
}

/**
 * Release using SRP
 */
static pi_error_t srp_release(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    
    mask = disable();
    
    if (res->owner != current) {
        restore(mask);
        return PI_ERROR_NOT_OWNER;
    }
    
    if (res->lock_count > 1) {
        res->lock_count--;
        restore(mask);
        return PI_OK;
    }
    
    /* Statistics */
    uint64_t hold_time = pc_system.system_time - res->acquire_time;
    res->total_hold_time += hold_time;
    if (hold_time > res->max_hold_time) {
        res->max_hold_time = hold_time;
    }
    
    pc_process_t *proc = get_pc_process(current);
    if (proc != NULL) {
        remove_pc_held(proc, id);
    }
    
    if (res->wait_count > 0) {
        pid32 next = dequeue_waiter(res);
        pc_process_t *next_proc = get_pc_process(next);
        
        res->owner = next;
        res->lock_count = 1;
        res->acquire_time = pc_system.system_time;
        res->acquisitions++;
        
        if (next_proc != NULL) {
            add_pc_held(next_proc, id);
        }
        
        proctab[next].pstate = PR_READY;
        ready(next, RESCHED_NO);
    } else {
        res->count++;
        res->owner = PI_INVALID_PID;
        res->lock_count = 0;
    }
    
    srp_update_system_level();
    resched();
    
    restore(mask);
    return PI_OK;
}


/**
 * Acquire resource (dispatches to appropriate protocol)
 */
pi_error_t pc_acquire(int32_t id)
{
    if (!pc_system.initialized) {
        return PI_ERROR_NOT_INITIALIZED;
    }
    
    switch (active_variant) {
    case CEILING_IMMEDIATE:
        return ipcp_acquire(id);
    case CEILING_ORIGINAL:
        return opcp_acquire(id);
    case CEILING_SRP:
        return srp_acquire(id);
    default:
        return ipcp_acquire(id);
    }
}

/**
 * Try to acquire without blocking
 */
pi_error_t pc_try_acquire(int32_t id)
{
    intmask mask;
    
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pid32 current = currpid;
    pc_process_t *proc = get_pc_process(current);
    if (proc == NULL) {
        pc_register_process(current, proctab[current].pprio);
        proc = get_pc_process(current);
    }
    
    mask = disable();
    
    if (res->owner == current) {
        res->lock_count++;
        restore(mask);
        return PI_OK;
    }
    
    if (res->count > 0) {
        res->count--;
        res->owner = current;
        res->lock_count = 1;
        res->acquisitions++;
        add_pc_held(proc, id);
        
        if (active_variant == CEILING_IMMEDIATE && res->ceiling > proc->current_priority) {
            push_priority(proc, proc->current_priority);
            proc->current_priority = res->ceiling;
            proctab[current].pprio = res->ceiling;
        }
        
        update_system_ceiling();
        restore(mask);
        return PI_OK;
    }
    
    restore(mask);
    return PI_ERROR_RESOURCE_BUSY;
}

/**
 * Release resource
 */
pi_error_t pc_release(int32_t id)
{
    if (!pc_system.initialized) {
        return PI_ERROR_NOT_INITIALIZED;
    }
    
    switch (active_variant) {
    case CEILING_IMMEDIATE:
        return ipcp_release(id);
    case CEILING_ORIGINAL:
        return opcp_release(id);
    case CEILING_SRP:
        return srp_release(id);
    default:
        return ipcp_release(id);
    }
}


/**
 * Timer tick
 */
void pc_tick(void)
{
    pc_system.system_time++;
}

/**
 * Get statistics
 */
void pc_get_stats(pi_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }
    
    stats->inversions_prevented = pc_system.total_blockings;
    stats->inheritance_events = 0;  /* Ceiling doesn't use inheritance */
    stats->ceiling_raises = pc_system.total_ceiling_raises;
    stats->deadlocks_detected = 0;  /* Ceiling prevents deadlocks */
    
    stats->total_blocking_time = 0;
    stats->max_blocking_time = 0;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        if (pc_resources[i].initialized) {
            stats->total_blocking_time += pc_resources[i].blocking_time;
            if (pc_resources[i].max_hold_time > stats->max_blocking_time) {
                stats->max_blocking_time = pc_resources[i].max_hold_time;
            }
        }
    }
}

/**
 * Print statistics
 */
void pc_print_stats(void)
{
    const char *variant_names[] = {"OPCP", "IPCP", "SRP"};
    
    kprintf("\n=== Priority Ceiling Statistics ===\n");
    kprintf("Variant: %s\n", variant_names[active_variant]);
    kprintf("System time: %llu ticks\n", pc_system.system_time);
    kprintf("System ceiling: %u\n", pc_system.system_ceiling);
    
    if (active_variant == CEILING_SRP) {
        kprintf("System preemption level: %u\n", pc_system.system_preemption_level);
    }
    
    kprintf("\n");
    kprintf("Total ceiling raises: %llu\n", pc_system.total_ceiling_raises);
    kprintf("Total blockings: %llu\n", pc_system.total_blockings);
    kprintf("Deadlocks prevented: %llu\n", pc_system.deadlocks_prevented);
    
    kprintf("\nPer-resource statistics:\n");
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        pc_resource_t *res = &pc_resources[i];
        if (res->initialized) {
            kprintf("  Resource %d (%s): ceiling=%u, acq=%llu, cont=%llu\n",
                    i, res->name ? res->name : "unnamed",
                    res->ceiling, res->acquisitions, res->contentions);
        }
    }
}

/**
 * Print resource
 */
void pc_print_resource(int32_t id)
{
    pc_resource_t *res = get_pc_resource(id);
    if (res == NULL) {
        kprintf("Resource %d: not initialized\n", id);
        return;
    }
    
    kprintf("\nResource %d (%s):\n", id, res->name ? res->name : "unnamed");
    kprintf("  Count: %d/%d, Owner: %d\n", res->count, res->max_count, res->owner);
    kprintf("  Ceiling: %u (computed: %u)\n", res->ceiling, res->computed_ceiling);
    kprintf("  Preemption level: %u\n", res->preemption_level);
    kprintf("  Wait queue: %u waiters\n", res->wait_count);
    kprintf("  Statistics:\n");
    kprintf("    Acquisitions: %llu\n", res->acquisitions);
    kprintf("    Contentions: %llu\n", res->contentions);
    kprintf("    Ceiling raises: %llu\n", res->ceiling_raises);
    kprintf("    Total hold time: %llu\n", res->total_hold_time);
    kprintf("    Max hold time: %llu\n", res->max_hold_time);
}

/**
 * Debug enable
 */
void pc_debug_enable(bool enable)
{
    pc_system.debug_enabled = enable;
}

/**
 * Validate state
 */
bool pc_validate(void)
{
    bool valid = true;
    
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        pc_resource_t *res = &pc_resources[i];
        if (!res->initialized) continue;
        
        /* Check owner consistency */
        if (res->owner != PI_INVALID_PID) {
            pc_process_t *owner = get_pc_process(res->owner);
            if (owner == NULL) {
                kprintf("PC validate: Resource %d has invalid owner %d\n",
                        i, res->owner);
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
                    kprintf("PC validate: Resource %d not in owner's held list\n", i);
                    valid = false;
                }
            }
        }
    }
    
    return valid;
}
