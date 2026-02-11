/*
 * deadlock.h - Deadlock Detection and Prevention Interface
 */

#ifndef _DEADLOCK_H_
#define _DEADLOCK_H_

#include "../include/kernel.h"
#include "priority_inversion.h"
#include <stdbool.h>
#include <stdint.h>


#define DL_MAX_PROCESSES      256       // Maximum processes in graph
#define DL_MAX_RESOURCES      128       // Maximum resources tracked
#define DL_MAX_CYCLE_LENGTH   32        // Maximum cycle length to detect
#define DL_DETECTION_INTERVAL 1000      // Detection interval (ms)


typedef enum {
    DL_STRATEGY_WAIT_FOR,           // Wait-for graph (process-only)
    DL_STRATEGY_RAG,                // Resource allocation graph
    DL_STRATEGY_COMBINED,           // Both methods combined
    DL_STRATEGY_TIMEOUT             // Timeout-based detection
} dl_strategy_t;


typedef enum {
    DL_ACTION_NONE,                 // No action
    DL_ACTION_ABORT_YOUNGEST,       // Abort youngest process
    DL_ACTION_ABORT_OLDEST,         // Abort oldest process
    DL_ACTION_ABORT_LOWEST_PRIORITY,// Abort lowest priority
    DL_ACTION_ABORT_LEAST_WORK,     // Abort with least work done
    DL_ACTION_ROLLBACK,             // Rollback to checkpoint
    DL_ACTION_PREEMPT_RESOURCE      // Preempt resource
} dl_action_t;


typedef enum {
    DL_EDGE_REQUEST,                // Process requests resource
    DL_EDGE_ASSIGNMENT,             // Resource assigned to process
    DL_EDGE_WAIT                    // Process waits for process
} dl_edge_type_t;


typedef struct dl_wfg_edge {
    pid32           from;           // Waiting process
    pid32           to;             // Process holding resource
    int32_t         resource_id;    // Resource causing wait
    uint64_t        wait_start;     // When wait began
    struct dl_wfg_edge *next;       // Next edge from same process
} dl_wfg_edge_t;


typedef struct dl_rag_edge {
    dl_edge_type_t  type;           // Edge type
    int32_t         process_id;     // Process (for request/assignment)
    int32_t         resource_id;    // Resource
    uint32_t        units;          // Number of units
    struct dl_rag_edge *next;       // Next edge
} dl_rag_edge_t;


typedef struct {
    pid32           pid;            // Process ID
    bool            active;         // Is process active
    dl_wfg_edge_t   *wait_edges;    // Edges to processes we wait for
    uint32_t        held_count;     // Resources held
    uint32_t        wait_count;     // Resources waiting for
    uint64_t        total_wait_time;// Cumulative wait time
    bool            visited;        // For graph traversal
    bool            on_stack;       // For cycle detection (DFS)
    int32_t         discovery;      // Discovery time (Tarjan's)
    int32_t         low_link;       // Low link value (Tarjan's)
} dl_process_node_t;


typedef struct {
    int32_t         resource_id;    // Resource identifier
    bool            active;         // Is resource active
    uint32_t        total_units;    // Total available units
    uint32_t        available;      // Currently available
    pid32           *holders;       // Processes holding resource
    uint32_t        holder_count;   // Number of holders
    pid32           *waiters;       // Processes waiting
    uint32_t        waiter_count;   // Number of waiters
} dl_resource_node_t;


typedef struct {
    bool            found;          // Was cycle detected
    uint32_t        length;         // Cycle length
    pid32           processes[DL_MAX_CYCLE_LENGTH];  // Processes in cycle
    int32_t         resources[DL_MAX_CYCLE_LENGTH];  // Resources in cycle
    uint64_t        detection_time; // When detected
    pid32           victim;         // Chosen victim for resolution
} dl_cycle_info_t;


typedef struct {
    uint64_t        total_checks;       // Total detection runs
    uint64_t        cycles_detected;    // Number of cycles found
    uint64_t        deadlocks_resolved; // Deadlocks resolved
    uint64_t        processes_aborted;  // Processes aborted
    uint64_t        resources_preempted;// Resources preempted
    uint64_t        false_positives;    // False positive detections
    uint64_t        total_check_time;   // Cumulative check time (us)
    uint64_t        max_check_time;     // Maximum single check time
    uint64_t        avg_cycle_length;   // Average cycle length
    uint64_t        max_cycle_length;   // Maximum cycle length
} dl_stats_t;


typedef struct {
    dl_strategy_t   strategy;           // Detection strategy
    dl_action_t     default_action;     // Default resolution action
    uint32_t        check_interval;     // Check interval (ms)
    uint32_t        wait_timeout;       // Wait timeout for timeout strategy
    bool            auto_resolve;       // Automatically resolve deadlocks
    bool            log_detections;     // Log when deadlock detected
    bool            enabled;            // Is detection enabled
} dl_config_t;


typedef struct {
    dl_config_t     config;             // Configuration
    dl_process_node_t processes[DL_MAX_PROCESSES];   // Process nodes
    dl_resource_node_t resources[DL_MAX_RESOURCES];  // Resource nodes
    dl_cycle_info_t last_cycle;         // Last detected cycle
    dl_stats_t      stats;              // Statistics
    bool            initialized;        // Is initialized
    uint64_t        last_check_time;    // Last check timestamp
} dl_detector_t;


extern dl_detector_t deadlock_detector;


/**
 * Initialize deadlock detector
 */
pi_error_t dl_init(dl_strategy_t strategy, dl_action_t default_action);

/**
 * Shutdown deadlock detector
 */
void dl_shutdown(void);

/**
 * Configure deadlock detector
 */
pi_error_t dl_configure(const dl_config_t *config);


/**
 * Add process to graph
 */
pi_error_t dl_add_process(pid32 pid);

/**
 * Remove process from graph
 */
pi_error_t dl_remove_process(pid32 pid);

/**
 * Add resource to graph
 */
pi_error_t dl_add_resource(int32_t resource_id, uint32_t units);

/**
 * Remove resource from graph
 */
pi_error_t dl_remove_resource(int32_t resource_id);


/**
 * Record process requesting resource
 */
pi_error_t dl_request_resource(pid32 pid, int32_t resource_id);

/**
 * Record resource assigned to process
 */
pi_error_t dl_assign_resource(pid32 pid, int32_t resource_id);

/**
 * Record process releasing resource
 */
pi_error_t dl_release_resource(pid32 pid, int32_t resource_id);

/**
 * Add wait-for edge
 */
pi_error_t dl_add_wait_edge(pid32 waiter, pid32 holder, int32_t resource_id);

/**
 * Remove wait-for edge
 */
pi_error_t dl_remove_wait_edge(pid32 waiter, pid32 holder);


/**
 * Run deadlock detection
 */
bool dl_detect(dl_cycle_info_t *cycle_info);

/**
 * Check if specific process is in deadlock
 */
bool dl_is_deadlocked(pid32 pid);

/**
 * Detect cycles using DFS
 */
bool dl_detect_cycle_dfs(pid32 start_pid, dl_cycle_info_t *cycle_info);

/**
 * Detect strongly connected components (Tarjan's algorithm)
 */
uint32_t dl_detect_scc(void);

/**
 * Check for resource allocation graph deadlock
 */
bool dl_detect_rag(dl_cycle_info_t *cycle_info);


/**
 * Resolve detected deadlock
 */
pi_error_t dl_resolve(dl_cycle_info_t *cycle_info, dl_action_t action);

/**
 * Select victim process
 */
pid32 dl_select_victim(dl_cycle_info_t *cycle_info, dl_action_t action);

/**
 * Abort process to break deadlock
 */
pi_error_t dl_abort_process(pid32 pid);

/**
 * Preempt resource from process
 */
pi_error_t dl_preempt_resource(pid32 pid, int32_t resource_id);


/**
 * Check if request would cause deadlock (banker's algorithm style)
 */
bool dl_would_deadlock(pid32 pid, int32_t resource_id);

/**
 * Get safe resource ordering
 */
pi_error_t dl_get_safe_order(int32_t *order, uint32_t *count);


/**
 * Get processes waiting for a resource
 */
uint32_t dl_get_waiters(int32_t resource_id, pid32 *waiters, uint32_t max);

/**
 * Get resources held by a process
 */
uint32_t dl_get_held(pid32 pid, int32_t *resources, uint32_t max);

/**
 * Get wait chain from process
 */
uint32_t dl_get_wait_chain(pid32 pid, pid32 *chain, uint32_t max);


/**
 * Get deadlock statistics
 */
void dl_get_stats(dl_stats_t *stats);

/**
 * Reset statistics
 */
void dl_reset_stats(void);

/**
 * Print statistics
 */
void dl_print_stats(void);

/**
 * Print wait-for graph
 */
void dl_print_graph(void);


/**
 * Start periodic deadlock detection
 */
pi_error_t dl_start_periodic(uint32_t interval_ms);

/**
 * Stop periodic detection
 */
void dl_stop_periodic(void);

/**
 * Deadlock detection callback type
 */
typedef void (*dl_callback_t)(dl_cycle_info_t *cycle_info);

/**
 * Register detection callback
 */
pi_error_t dl_register_callback(dl_callback_t callback);

#endif /* _DEADLOCK_H_ */
