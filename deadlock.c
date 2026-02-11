
// deadlock.c - Deadlock Detection Implementation

#include "deadlock.h"
#include "../include/kernel.h"
#include "../include/process.h"
#include "../include/interrupts.h"
#include <string.h>


dl_detector_t deadlock_detector;

static dl_wfg_edge_t edge_pool[DL_MAX_PROCESSES * 4];
static bool edge_used[DL_MAX_PROCESSES * 4];

static pid32 holder_arrays[DL_MAX_RESOURCES][16];
static pid32 waiter_arrays[DL_MAX_RESOURCES][32];

static dl_callback_t detection_callback = NULL;

static int32_t dfs_time = 0;
static pid32 dfs_stack[DL_MAX_PROCESSES];
static int32_t dfs_stack_top = 0;


static dl_wfg_edge_t *alloc_edge(void)
{
    for (int i = 0; i < DL_MAX_PROCESSES * 4; i++) {
        if (!edge_used[i]) {
            edge_used[i] = true;
            memset(&edge_pool[i], 0, sizeof(dl_wfg_edge_t));
            return &edge_pool[i];
        }
    }
    return NULL;
}

static void free_edge(dl_wfg_edge_t *edge)
{
    if (edge) {
        int idx = edge - edge_pool;
        if (idx >= 0 && idx < DL_MAX_PROCESSES * 4) {
            edge_used[idx] = false;
        }
    }
}


/**
 * Initialize deadlock detector
 */
pi_error_t dl_init(dl_strategy_t strategy, dl_action_t default_action)
{
    intmask mask = disable();
    
    /* Clear all state */
    memset(&deadlock_detector, 0, sizeof(dl_detector_t));
    memset(edge_pool, 0, sizeof(edge_pool));
    memset(edge_used, 0, sizeof(edge_used));
    
    /* Set configuration */
    deadlock_detector.config.strategy = strategy;
    deadlock_detector.config.default_action = default_action;
    deadlock_detector.config.check_interval = DL_DETECTION_INTERVAL;
    deadlock_detector.config.wait_timeout = 5000;
    deadlock_detector.config.auto_resolve = false;
    deadlock_detector.config.log_detections = true;
    deadlock_detector.config.enabled = true;
    
    /* Initialize resource holder/waiter arrays */
    for (int i = 0; i < DL_MAX_RESOURCES; i++) {
        deadlock_detector.resources[i].holders = holder_arrays[i];
        deadlock_detector.resources[i].waiters = waiter_arrays[i];
    }
    
    deadlock_detector.initialized = true;
    
    restore(mask);
    return PI_OK;
}

/**
 * Shutdown deadlock detector
 */
void dl_shutdown(void)
{
    intmask mask = disable();
    
    /* Free all edges */
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        dl_wfg_edge_t *edge = deadlock_detector.processes[i].wait_edges;
        while (edge) {
            dl_wfg_edge_t *next = edge->next;
            free_edge(edge);
            edge = next;
        }
    }
    
    deadlock_detector.initialized = false;
    
    restore(mask);
}

/**
 * Configure deadlock detector
 */
pi_error_t dl_configure(const dl_config_t *config)
{
    if (config == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    memcpy(&deadlock_detector.config, config, sizeof(dl_config_t));
    restore(mask);
    
    return PI_OK;
}


/**
 * Add process to graph
 */
pi_error_t dl_add_process(pid32 pid)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *node = &deadlock_detector.processes[pid];
    if (node->active) {
        restore(mask);
        return PI_ERROR_INVALID_OPERATION;
    }
    
    memset(node, 0, sizeof(dl_process_node_t));
    node->pid = pid;
    node->active = true;
    node->discovery = -1;
    node->low_link = -1;
    
    restore(mask);
    return PI_OK;
}

/**
 * Remove process from graph
 */
pi_error_t dl_remove_process(pid32 pid)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *node = &deadlock_detector.processes[pid];
    if (!node->active) {
        restore(mask);
        return PI_ERROR_INVALID_PROCESS;
    }
    
    /* Free all edges from this process */
    dl_wfg_edge_t *edge = node->wait_edges;
    while (edge) {
        dl_wfg_edge_t *next = edge->next;
        free_edge(edge);
        edge = next;
    }
    
    /* Remove from all resource holder/waiter lists */
    for (int i = 0; i < DL_MAX_RESOURCES; i++) {
        dl_resource_node_t *res = &deadlock_detector.resources[i];
        if (!res->active) continue;
        
        /* Remove from holders */
        for (uint32_t j = 0; j < res->holder_count; j++) {
            if (res->holders[j] == pid) {
                res->holders[j] = res->holders[--res->holder_count];
                break;
            }
        }
        
        /* Remove from waiters */
        for (uint32_t j = 0; j < res->waiter_count; j++) {
            if (res->waiters[j] == pid) {
                res->waiters[j] = res->waiters[--res->waiter_count];
                break;
            }
        }
    }
    
    node->active = false;
    
    restore(mask);
    return PI_OK;
}

/**
 * Add resource to graph
 */
pi_error_t dl_add_resource(int32_t resource_id, uint32_t units)
{
    if (resource_id < 0 || resource_id >= DL_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    
    dl_resource_node_t *node = &deadlock_detector.resources[resource_id];
    if (node->active) {
        restore(mask);
        return PI_ERROR_INVALID_OPERATION;
    }
    
    node->resource_id = resource_id;
    node->active = true;
    node->total_units = units;
    node->available = units;
    node->holder_count = 0;
    node->waiter_count = 0;
    
    restore(mask);
    return PI_OK;
}

/**
 * Remove resource from graph
 */
pi_error_t dl_remove_resource(int32_t resource_id)
{
    if (resource_id < 0 || resource_id >= DL_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    
    dl_resource_node_t *node = &deadlock_detector.resources[resource_id];
    if (!node->active) {
        restore(mask);
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    /* Remove all wait edges involving this resource */
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        dl_process_node_t *proc = &deadlock_detector.processes[i];
        if (!proc->active) continue;
        
        dl_wfg_edge_t **pp = &proc->wait_edges;
        while (*pp) {
            if ((*pp)->resource_id == resource_id) {
                dl_wfg_edge_t *to_free = *pp;
                *pp = (*pp)->next;
                free_edge(to_free);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    
    node->active = false;
    
    restore(mask);
    return PI_OK;
}


/**
 * Record process requesting resource
 */
pi_error_t dl_request_resource(pid32 pid, int32_t resource_id)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    if (resource_id < 0 || resource_id >= DL_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *proc = &deadlock_detector.processes[pid];
    dl_resource_node_t *res = &deadlock_detector.resources[resource_id];
    
    if (!proc->active || !res->active) {
        restore(mask);
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    /* Add to waiter list if not already there */
    bool already_waiting = false;
    for (uint32_t i = 0; i < res->waiter_count; i++) {
        if (res->waiters[i] == pid) {
            already_waiting = true;
            break;
        }
    }
    
    if (!already_waiting && res->waiter_count < 32) {
        res->waiters[res->waiter_count++] = pid;
    }
    
    /* Add wait edges to all holders */
    for (uint32_t i = 0; i < res->holder_count; i++) {
        pid32 holder = res->holders[i];
        if (holder != pid) {
            dl_add_wait_edge(pid, holder, resource_id);
        }
    }
    
    proc->wait_count++;
    
    restore(mask);
    return PI_OK;
}

/**
 * Record resource assigned to process
 */
pi_error_t dl_assign_resource(pid32 pid, int32_t resource_id)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    if (resource_id < 0 || resource_id >= DL_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *proc = &deadlock_detector.processes[pid];
    dl_resource_node_t *res = &deadlock_detector.resources[resource_id];
    
    if (!proc->active || !res->active) {
        restore(mask);
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    /* Remove from waiter list */
    for (uint32_t i = 0; i < res->waiter_count; i++) {
        if (res->waiters[i] == pid) {
            res->waiters[i] = res->waiters[--res->waiter_count];
            break;
        }
    }
    
    /* Add to holder list */
    bool already_holder = false;
    for (uint32_t i = 0; i < res->holder_count; i++) {
        if (res->holders[i] == pid) {
            already_holder = true;
            break;
        }
    }
    
    if (!already_holder && res->holder_count < 16) {
        res->holders[res->holder_count++] = pid;
    }
    
    /* Remove wait edges to previous holders */
    dl_wfg_edge_t **pp = &proc->wait_edges;
    while (*pp) {
        if ((*pp)->resource_id == resource_id) {
            dl_wfg_edge_t *to_free = *pp;
            *pp = (*pp)->next;
            free_edge(to_free);
        } else {
            pp = &(*pp)->next;
        }
    }
    
    if (res->available > 0) res->available--;
    proc->held_count++;
    if (proc->wait_count > 0) proc->wait_count--;
    
    restore(mask);
    return PI_OK;
}

/**
 * Record process releasing resource
 */
pi_error_t dl_release_resource(pid32 pid, int32_t resource_id)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    if (resource_id < 0 || resource_id >= DL_MAX_RESOURCES) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *proc = &deadlock_detector.processes[pid];
    dl_resource_node_t *res = &deadlock_detector.resources[resource_id];
    
    if (!proc->active || !res->active) {
        restore(mask);
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    /* Remove from holder list */
    for (uint32_t i = 0; i < res->holder_count; i++) {
        if (res->holders[i] == pid) {
            res->holders[i] = res->holders[--res->holder_count];
            break;
        }
    }
    
    /* Remove wait edges from other processes to this process for this resource */
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        if (i == pid) continue;
        dl_process_node_t *other = &deadlock_detector.processes[i];
        if (!other->active) continue;
        
        dl_wfg_edge_t **pp = &other->wait_edges;
        while (*pp) {
            if ((*pp)->to == pid && (*pp)->resource_id == resource_id) {
                dl_wfg_edge_t *to_free = *pp;
                *pp = (*pp)->next;
                free_edge(to_free);
            } else {
                pp = &(*pp)->next;
            }
        }
    }
    
    if (res->available < res->total_units) res->available++;
    if (proc->held_count > 0) proc->held_count--;
    
    restore(mask);
    return PI_OK;
}

/**
 * Add wait-for edge
 */
pi_error_t dl_add_wait_edge(pid32 waiter, pid32 holder, int32_t resource_id)
{
    if (waiter < 0 || waiter >= DL_MAX_PROCESSES ||
        holder < 0 || holder >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *wait_node = &deadlock_detector.processes[waiter];
    
    if (!wait_node->active) {
        restore(mask);
        return PI_ERROR_INVALID_PROCESS;
    }
    
    /* Check if edge already exists */
    dl_wfg_edge_t *edge = wait_node->wait_edges;
    while (edge) {
        if (edge->to == holder && edge->resource_id == resource_id) {
            restore(mask);
            return PI_OK;  /* Already exists */
        }
        edge = edge->next;
    }
    
    /* Allocate new edge */
    edge = alloc_edge();
    if (edge == NULL) {
        restore(mask);
        return PI_ERROR_NO_MEMORY;
    }
    
    edge->from = waiter;
    edge->to = holder;
    edge->resource_id = resource_id;
    edge->wait_start = 0; /* Would use get_time() in real implementation */
    edge->next = wait_node->wait_edges;
    wait_node->wait_edges = edge;
    
    restore(mask);
    return PI_OK;
}

/**
 * Remove wait-for edge
 */
pi_error_t dl_remove_wait_edge(pid32 waiter, pid32 holder)
{
    if (waiter < 0 || waiter >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    intmask mask = disable();
    
    dl_process_node_t *wait_node = &deadlock_detector.processes[waiter];
    
    if (!wait_node->active) {
        restore(mask);
        return PI_ERROR_INVALID_PROCESS;
    }
    
    dl_wfg_edge_t **pp = &wait_node->wait_edges;
    while (*pp) {
        if ((*pp)->to == holder) {
            dl_wfg_edge_t *to_free = *pp;
            *pp = (*pp)->next;
            free_edge(to_free);
            restore(mask);
            return PI_OK;
        }
        pp = &(*pp)->next;
    }
    
    restore(mask);
    return PI_ERROR_INVALID_RESOURCE;
}


/**
 * DFS helper for cycle detection
 */
static bool dfs_visit(pid32 pid, dl_cycle_info_t *cycle_info, 
                      pid32 *path, uint32_t *path_len)
{
    dl_process_node_t *node = &deadlock_detector.processes[pid];
    
    node->visited = true;
    node->on_stack = true;
    
    /* Add to path */
    if (*path_len < DL_MAX_CYCLE_LENGTH) {
        path[(*path_len)++] = pid;
    }
    
    /* Check all wait edges */
    dl_wfg_edge_t *edge = node->wait_edges;
    while (edge) {
        pid32 target = edge->to;
        dl_process_node_t *target_node = &deadlock_detector.processes[target];
        
        if (!target_node->active) {
            edge = edge->next;
            continue;
        }
        
        if (target_node->on_stack) {
            /* Found cycle! */
            cycle_info->found = true;
            cycle_info->length = 0;
            
            /* Extract cycle from path */
            bool in_cycle = false;
            for (uint32_t i = 0; i < *path_len && cycle_info->length < DL_MAX_CYCLE_LENGTH; i++) {
                if (path[i] == target) {
                    in_cycle = true;
                }
                if (in_cycle) {
                    cycle_info->processes[cycle_info->length++] = path[i];
                }
            }
            
            node->on_stack = false;
            return true;
        }
        
        if (!target_node->visited) {
            if (dfs_visit(target, cycle_info, path, path_len)) {
                node->on_stack = false;
                return true;
            }
        }
        
        edge = edge->next;
    }
    
    node->on_stack = false;
    if (*path_len > 0) (*path_len)--;
    
    return false;
}

/**
 * Run deadlock detection
 */
bool dl_detect(dl_cycle_info_t *cycle_info)
{
    if (!deadlock_detector.initialized || !deadlock_detector.config.enabled) {
        return false;
    }
    
    intmask mask = disable();
    
    deadlock_detector.stats.total_checks++;
    
    /* Reset traversal state */
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        deadlock_detector.processes[i].visited = false;
        deadlock_detector.processes[i].on_stack = false;
    }
    
    /* Initialize cycle info */
    dl_cycle_info_t local_cycle;
    if (cycle_info == NULL) {
        cycle_info = &local_cycle;
    }
    memset(cycle_info, 0, sizeof(dl_cycle_info_t));
    
    pid32 path[DL_MAX_CYCLE_LENGTH];
    uint32_t path_len = 0;
    
    /* DFS from each unvisited node */
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        dl_process_node_t *node = &deadlock_detector.processes[i];
        if (node->active && !node->visited && node->wait_edges != NULL) {
            path_len = 0;
            if (dfs_visit(i, cycle_info, path, &path_len)) {
                deadlock_detector.stats.cycles_detected++;
                
                if (deadlock_detector.config.log_detections) {
                    kprintf("Deadlock detected! Cycle length: %u\n", cycle_info->length);
                }
                
                /* Store last cycle */
                memcpy(&deadlock_detector.last_cycle, cycle_info, sizeof(dl_cycle_info_t));
                
                /* Call callback if registered */
                if (detection_callback) {
                    restore(mask);
                    detection_callback(cycle_info);
                    mask = disable();
                }
                
                /* Auto-resolve if configured */
                if (deadlock_detector.config.auto_resolve) {
                    dl_resolve(cycle_info, deadlock_detector.config.default_action);
                }
                
                restore(mask);
                return true;
            }
        }
    }
    
    restore(mask);
    return false;
}

/**
 * Check if specific process is in deadlock
 */
bool dl_is_deadlocked(pid32 pid)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return false;
    }
    
    dl_cycle_info_t cycle_info;
    if (dl_detect(&cycle_info)) {
        for (uint32_t i = 0; i < cycle_info.length; i++) {
            if (cycle_info.processes[i] == pid) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Detect cycles using DFS starting from specific process
 */
bool dl_detect_cycle_dfs(pid32 start_pid, dl_cycle_info_t *cycle_info)
{
    if (start_pid < 0 || start_pid >= DL_MAX_PROCESSES) {
        return false;
    }
    
    intmask mask = disable();
    
    /* Reset traversal state */
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        deadlock_detector.processes[i].visited = false;
        deadlock_detector.processes[i].on_stack = false;
    }
    
    memset(cycle_info, 0, sizeof(dl_cycle_info_t));
    
    pid32 path[DL_MAX_CYCLE_LENGTH];
    uint32_t path_len = 0;
    
    bool found = dfs_visit(start_pid, cycle_info, path, &path_len);
    
    restore(mask);
    return found;
}

/**
 * Tarjan's SCC algorithm helper
 */
static void tarjan_visit(pid32 pid, int32_t *scc_count)
{
    dl_process_node_t *node = &deadlock_detector.processes[pid];
    
    node->discovery = dfs_time;
    node->low_link = dfs_time;
    dfs_time++;
    
    dfs_stack[dfs_stack_top++] = pid;
    node->on_stack = true;
    
    /* Visit all neighbors */
    dl_wfg_edge_t *edge = node->wait_edges;
    while (edge) {
        pid32 target = edge->to;
        dl_process_node_t *target_node = &deadlock_detector.processes[target];
        
        if (target_node->active) {
            if (target_node->discovery < 0) {
                tarjan_visit(target, scc_count);
                if (target_node->low_link < node->low_link) {
                    node->low_link = target_node->low_link;
                }
            } else if (target_node->on_stack) {
                if (target_node->discovery < node->low_link) {
                    node->low_link = target_node->discovery;
                }
            }
        }
        
        edge = edge->next;
    }
    
    /* If this is a root node, pop the SCC */
    if (node->low_link == node->discovery) {
        int scc_size = 0;
        pid32 w;
        do {
            w = dfs_stack[--dfs_stack_top];
            deadlock_detector.processes[w].on_stack = false;
            scc_size++;
        } while (w != pid);
        
        /* SCC with more than one node indicates a cycle (potential deadlock) */
        if (scc_size > 1) {
            (*scc_count)++;
        }
    }
}

/**
 * Detect strongly connected components
 */
uint32_t dl_detect_scc(void)
{
    intmask mask = disable();
    
    /* Reset state */
    dfs_time = 0;
    dfs_stack_top = 0;
    
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        deadlock_detector.processes[i].discovery = -1;
        deadlock_detector.processes[i].low_link = -1;
        deadlock_detector.processes[i].on_stack = false;
    }
    
    int32_t scc_count = 0;
    
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        dl_process_node_t *node = &deadlock_detector.processes[i];
        if (node->active && node->discovery < 0) {
            tarjan_visit(i, &scc_count);
        }
    }
    
    restore(mask);
    return scc_count;
}

/**
 * Resource allocation graph deadlock detection
 */
bool dl_detect_rag(dl_cycle_info_t *cycle_info)
{
    /* For single-instance resources, RAG is equivalent to WFG */
    /* For multi-instance, we need to use banker's algorithm */
    
    /* For now, delegate to regular detection */
    return dl_detect(cycle_info);
}


/**
 * Select victim process
 */
pid32 dl_select_victim(dl_cycle_info_t *cycle_info, dl_action_t action)
{
    if (cycle_info == NULL || cycle_info->length == 0) {
        return PI_INVALID_PID;
    }
    
    pid32 victim = cycle_info->processes[0];
    
    switch (action) {
    case DL_ACTION_ABORT_YOUNGEST:
        /* Would need process creation time */
        victim = cycle_info->processes[cycle_info->length - 1];
        break;
        
    case DL_ACTION_ABORT_OLDEST:
        victim = cycle_info->processes[0];
        break;
        
    case DL_ACTION_ABORT_LOWEST_PRIORITY:
        /* Find lowest priority in cycle */
        {
            pri16 lowest = MAXINT16;
            for (uint32_t i = 0; i < cycle_info->length; i++) {
                pid32 pid = cycle_info->processes[i];
                /* Would get priority from process table */
                pri16 pri = 10;  /* Placeholder */
                if (pri < lowest) {
                    lowest = pri;
                    victim = pid;
                }
            }
        }
        break;
        
    case DL_ACTION_ABORT_LEAST_WORK:
        /* Find process with least resources held */
        {
            uint32_t min_held = MAXINT32;
            for (uint32_t i = 0; i < cycle_info->length; i++) {
                pid32 pid = cycle_info->processes[i];
                dl_process_node_t *node = &deadlock_detector.processes[pid];
                if (node->held_count < min_held) {
                    min_held = node->held_count;
                    victim = pid;
                }
            }
        }
        break;
        
    default:
        victim = cycle_info->processes[0];
        break;
    }
    
    return victim;
}

/**
 * Resolve detected deadlock
 */
pi_error_t dl_resolve(dl_cycle_info_t *cycle_info, dl_action_t action)
{
    if (cycle_info == NULL || !cycle_info->found) {
        return PI_ERROR_INVALID_OPERATION;
    }
    
    pid32 victim = dl_select_victim(cycle_info, action);
    cycle_info->victim = victim;
    
    pi_error_t result = PI_OK;
    
    switch (action) {
    case DL_ACTION_ABORT_YOUNGEST:
    case DL_ACTION_ABORT_OLDEST:
    case DL_ACTION_ABORT_LOWEST_PRIORITY:
    case DL_ACTION_ABORT_LEAST_WORK:
        result = dl_abort_process(victim);
        if (result == PI_OK) {
            deadlock_detector.stats.processes_aborted++;
            deadlock_detector.stats.deadlocks_resolved++;
        }
        break;
        
    case DL_ACTION_PREEMPT_RESOURCE:
        /* Preempt one resource from victim */
        {
            dl_process_node_t *node = &deadlock_detector.processes[victim];
            dl_wfg_edge_t *edge = node->wait_edges;
            if (edge) {
                result = dl_preempt_resource(edge->to, edge->resource_id);
                if (result == PI_OK) {
                    deadlock_detector.stats.resources_preempted++;
                    deadlock_detector.stats.deadlocks_resolved++;
                }
            }
        }
        break;
        
    case DL_ACTION_NONE:
    default:
        break;
    }
    
    return result;
}

/**
 * Abort process to break deadlock
 */
pi_error_t dl_abort_process(pid32 pid)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    kprintf("Deadlock resolution: aborting process %d\n", pid);
    
    /* Release all resources held by process */
    dl_process_node_t *node = &deadlock_detector.processes[pid];
    
    for (int i = 0; i < DL_MAX_RESOURCES; i++) {
        dl_resource_node_t *res = &deadlock_detector.resources[i];
        if (!res->active) continue;
        
        for (uint32_t j = 0; j < res->holder_count; j++) {
            if (res->holders[j] == pid) {
                dl_release_resource(pid, i);
                break;
            }
        }
    }
    
    /* Remove process from graph */
    dl_remove_process(pid);
    
    /* In a real system, would also kill/abort the actual process */
    /* kill(pid); */
    
    return PI_OK;
}

/**
 * Preempt resource from process
 */
pi_error_t dl_preempt_resource(pid32 pid, int32_t resource_id)
{
    kprintf("Deadlock resolution: preempting resource %d from process %d\n",
            resource_id, pid);
    
    /* Release the resource */
    return dl_release_resource(pid, resource_id);
}


/**
 * Check if request would cause deadlock (simple check)
 */
bool dl_would_deadlock(pid32 pid, int32_t resource_id)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES ||
        resource_id < 0 || resource_id >= DL_MAX_RESOURCES) {
        return true;  /* Invalid = unsafe */
    }
    
    intmask mask = disable();
    
    /* Temporarily add the request and check for cycle */
    dl_request_resource(pid, resource_id);
    
    dl_cycle_info_t cycle_info;
    bool would_deadlock = dl_detect_cycle_dfs(pid, &cycle_info);
    
    /* Remove the temporary request */
    dl_process_node_t *proc = &deadlock_detector.processes[pid];
    dl_resource_node_t *res = &deadlock_detector.resources[resource_id];
    
    /* Remove from waiter list */
    for (uint32_t i = 0; i < res->waiter_count; i++) {
        if (res->waiters[i] == pid) {
            res->waiters[i] = res->waiters[--res->waiter_count];
            break;
        }
    }
    
    /* Remove wait edges for this resource */
    dl_wfg_edge_t **pp = &proc->wait_edges;
    while (*pp) {
        if ((*pp)->resource_id == resource_id) {
            dl_wfg_edge_t *to_free = *pp;
            *pp = (*pp)->next;
            free_edge(to_free);
        } else {
            pp = &(*pp)->next;
        }
    }
    
    if (proc->wait_count > 0) proc->wait_count--;
    
    restore(mask);
    return would_deadlock;
}

/**
 * Get safe resource ordering (simplified)
 */
pi_error_t dl_get_safe_order(int32_t *order, uint32_t *count)
{
    if (order == NULL || count == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    intmask mask = disable();
    
    *count = 0;
    
    /* Simple topological sort based on resource IDs */
    for (int i = 0; i < DL_MAX_RESOURCES; i++) {
        if (deadlock_detector.resources[i].active) {
            order[(*count)++] = i;
        }
    }
    
    restore(mask);
    return PI_OK;
}


/**
 * Get processes waiting for a resource
 */
uint32_t dl_get_waiters(int32_t resource_id, pid32 *waiters, uint32_t max)
{
    if (resource_id < 0 || resource_id >= DL_MAX_RESOURCES || waiters == NULL) {
        return 0;
    }
    
    intmask mask = disable();
    
    dl_resource_node_t *res = &deadlock_detector.resources[resource_id];
    uint32_t count = (res->waiter_count < max) ? res->waiter_count : max;
    
    for (uint32_t i = 0; i < count; i++) {
        waiters[i] = res->waiters[i];
    }
    
    restore(mask);
    return count;
}

/**
 * Get resources held by a process
 */
uint32_t dl_get_held(pid32 pid, int32_t *resources, uint32_t max)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES || resources == NULL) {
        return 0;
    }
    
    intmask mask = disable();
    
    uint32_t count = 0;
    
    for (int i = 0; i < DL_MAX_RESOURCES && count < max; i++) {
        dl_resource_node_t *res = &deadlock_detector.resources[i];
        if (!res->active) continue;
        
        for (uint32_t j = 0; j < res->holder_count; j++) {
            if (res->holders[j] == pid) {
                resources[count++] = i;
                break;
            }
        }
    }
    
    restore(mask);
    return count;
}

/**
 * Get wait chain from process
 */
uint32_t dl_get_wait_chain(pid32 pid, pid32 *chain, uint32_t max)
{
    if (pid < 0 || pid >= DL_MAX_PROCESSES || chain == NULL || max == 0) {
        return 0;
    }
    
    intmask mask = disable();
    
    uint32_t count = 0;
    pid32 current = pid;
    
    /* Follow wait edges */
    while (count < max) {
        dl_process_node_t *node = &deadlock_detector.processes[current];
        if (!node->active || node->wait_edges == NULL) {
            break;
        }
        
        chain[count++] = current;
        
        /* Check for cycle (we've seen this process before) */
        pid32 next = node->wait_edges->to;
        for (uint32_t i = 0; i < count; i++) {
            if (chain[i] == next) {
                chain[count++] = next;  /* Add to show cycle */
                restore(mask);
                return count;
            }
        }
        
        current = next;
    }
    
    restore(mask);
    return count;
}


/**
 * Get deadlock statistics
 */
void dl_get_stats(dl_stats_t *stats)
{
    if (stats) {
        intmask mask = disable();
        memcpy(stats, &deadlock_detector.stats, sizeof(dl_stats_t));
        restore(mask);
    }
}

/**
 * Reset statistics
 */
void dl_reset_stats(void)
{
    intmask mask = disable();
    memset(&deadlock_detector.stats, 0, sizeof(dl_stats_t));
    restore(mask);
}

/**
 * Print statistics
 */
void dl_print_stats(void)
{
    dl_stats_t *s = &deadlock_detector.stats;
    
    kprintf("\nDeadlock Detection Statistics:\n");
    kprintf("  Total checks:         %llu\n", s->total_checks);
    kprintf("  Cycles detected:      %llu\n", s->cycles_detected);
    kprintf("  Deadlocks resolved:   %llu\n", s->deadlocks_resolved);
    kprintf("  Processes aborted:    %llu\n", s->processes_aborted);
    kprintf("  Resources preempted:  %llu\n", s->resources_preempted);
    kprintf("  False positives:      %llu\n", s->false_positives);
}

/**
 * Print wait-for graph
 */
void dl_print_graph(void)
{
    kprintf("\nWait-For Graph:\n");
    
    for (int i = 0; i < DL_MAX_PROCESSES; i++) {
        dl_process_node_t *node = &deadlock_detector.processes[i];
        if (!node->active || node->wait_edges == NULL) {
            continue;
        }
        
        kprintf("  P%d waits for:", i);
        
        dl_wfg_edge_t *edge = node->wait_edges;
        while (edge) {
            kprintf(" P%d(R%d)", edge->to, edge->resource_id);
            edge = edge->next;
        }
        kprintf("\n");
    }
    
    kprintf("\nResource Allocation:\n");
    for (int i = 0; i < DL_MAX_RESOURCES; i++) {
        dl_resource_node_t *res = &deadlock_detector.resources[i];
        if (!res->active) continue;
        
        kprintf("  R%d: ", i);
        if (res->holder_count > 0) {
            kprintf("held by");
            for (uint32_t j = 0; j < res->holder_count; j++) {
                kprintf(" P%d", res->holders[j]);
            }
        }
        if (res->waiter_count > 0) {
            kprintf(" | requested by");
            for (uint32_t j = 0; j < res->waiter_count; j++) {
                kprintf(" P%d", res->waiters[j]);
            }
        }
        kprintf("\n");
    }
}


/**
 * Register detection callback
 */
pi_error_t dl_register_callback(dl_callback_t callback)
{
    intmask mask = disable();
    detection_callback = callback;
    restore(mask);
    return PI_OK;
}

/**
 * Start periodic deadlock detection
 */
pi_error_t dl_start_periodic(uint32_t interval_ms)
{
    deadlock_detector.config.check_interval = interval_ms;
    /* Would create a kernel thread for periodic checking */
    /* For now, just set the interval */
    return PI_OK;
}

/**
 * Stop periodic detection
 */
void dl_stop_periodic(void)
{
    /* Would stop the kernel thread */
}
