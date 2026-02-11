/*
 * analysis.h - Blocking Time Analysis Interface
 *
 * Provides worst-case blocking time computation for real-time schedulability
 * analysis with various priority inversion protocols.
 */

#ifndef _ANALYSIS_H_
#define _ANALYSIS_H_

#include "../include/kernel.h"
#include "priority_inversion.h"
#include <stdbool.h>
#include <stdint.h>

#define AN_MAX_TASKS            64      /* Maximum tasks to analyze */
#define AN_MAX_RESOURCES        32      /* Maximum resources per analysis */
#define AN_MAX_CRITICAL_SECTIONS 16     /* Max CS per task */
#define AN_PRECISION            1000    /* Time precision (microseconds) */

typedef struct {
    pid32           pid;                /* Process ID */
    pri16           priority;           /* Static priority */
    uint32_t        period;             /* Period (microseconds) */
    uint32_t        deadline;           /* Relative deadline */
    uint32_t        wcet;               /* Worst-case execution time */
    uint32_t        preemption_level;   /* For SRP */
    bool            active;             /* Is task active */
} an_task_params_t;

typedef struct {
    int32_t         resource_id;        /* Resource accessed */
    uint32_t        duration;           /* Critical section duration */
    bool            nested;             /* Is this nested within another CS */
    int32_t         outer_resource;     /* Outer resource if nested */
} an_critical_section_t;

typedef struct {
    an_task_params_t params;            /* Task parameters */
    an_critical_section_t cs[AN_MAX_CRITICAL_SECTIONS]; /* Critical sections */
    uint32_t        cs_count;           /* Number of critical sections */
    uint32_t        blocking_time;      /* Computed blocking time */
    uint32_t        response_time;      /* Computed response time */
    double          utilization;        /* Task utilization */
    bool            schedulable;        /* Can meet deadline */
} an_task_info_t;

typedef struct {
    int32_t         resource_id;        /* Resource ID */
    pri16           ceiling;            /* Priority ceiling */
    uint32_t        preemption_level;   /* SRP preemption level */
    uint32_t        max_hold_time;      /* Maximum hold time */
    pid32           users[AN_MAX_TASKS];/* Tasks that use this resource */
    uint32_t        user_count;         /* Number of users */
} an_resource_info_t;

typedef struct {
    /* Per-task results */
    uint32_t        blocking_times[AN_MAX_TASKS];
    uint32_t        response_times[AN_MAX_TASKS];
    bool            task_schedulable[AN_MAX_TASKS];
    
    /* System-wide results */
    double          total_utilization;
    double          blocking_overhead;
    bool            system_schedulable;
    
    /* Protocol comparison */
    uint32_t        pip_blocking[AN_MAX_TASKS];
    uint32_t        pcp_blocking[AN_MAX_TASKS];
    uint32_t        srp_blocking[AN_MAX_TASKS];
    
    /* Statistics */
    uint32_t        max_blocking;       /* Maximum blocking across all tasks */
    uint32_t        avg_blocking;       /* Average blocking time */
    uint32_t        max_response;       /* Maximum response time */
} an_results_t;

typedef struct {
    pi_protocol_t   protocol;           /* Protocol to analyze */
    bool            compute_response;   /* Compute response times */
    bool            compare_protocols;  /* Compare all protocols */
    uint32_t        max_iterations;     /* Max iterations for response time */
    uint32_t        convergence_threshold; /* Response time convergence */
} an_config_t;

typedef struct {
    an_config_t     config;
    an_task_info_t  tasks[AN_MAX_TASKS];
    uint32_t        task_count;
    an_resource_info_t resources[AN_MAX_RESOURCES];
    uint32_t        resource_count;
    an_results_t    results;
    bool            initialized;
} an_context_t;

extern an_context_t analysis_context;

/**
 * Initialize analysis context
 */
pi_error_t an_init(const an_config_t *config);

/**
 * Reset analysis context
 */
void an_reset(void);

/**
 * Configure analysis parameters
 */
pi_error_t an_configure(const an_config_t *config);

/**
 * Add task to analysis
 */
pi_error_t an_add_task(const an_task_params_t *params);

/**
 * Remove task from analysis
 */
pi_error_t an_remove_task(pid32 pid);

/**
 * Update task parameters
 */
pi_error_t an_update_task(pid32 pid, const an_task_params_t *params);

/**
 * Add critical section to task
 */
pi_error_t an_add_critical_section(pid32 pid, int32_t resource_id,
                                    uint32_t duration, bool nested,
                                    int32_t outer_resource);

/**
 * Add resource to analysis
 */
pi_error_t an_add_resource(int32_t resource_id, pri16 ceiling,
                           uint32_t preemption_level);

/**
 * Remove resource from analysis
 */
pi_error_t an_remove_resource(int32_t resource_id);

/**
 * Compute resource ceiling from task access
 */
pri16 an_compute_ceiling(int32_t resource_id);

/**
 * Compute SRP preemption level
 */
uint32_t an_compute_preemption_level(int32_t resource_id);

/**
 * Compute blocking time for a task using Priority Inheritance
 */
uint32_t an_blocking_pip(pid32 pid);

/**
 * Compute blocking time for a task using Priority Ceiling Protocol
 */
uint32_t an_blocking_pcp(pid32 pid);

/**
 * Compute blocking time for a task using Immediate PCP
 */
uint32_t an_blocking_ipcp(pid32 pid);

/**
 * Compute blocking time for a task using Stack Resource Policy
 */
uint32_t an_blocking_srp(pid32 pid);

/**
 * Compute blocking time based on configured protocol
 */
uint32_t an_blocking_time(pid32 pid);

/**
 * Compute maximum blocking by lower priority tasks
 */
uint32_t an_max_lower_blocking(pid32 pid);

/**
 * Compute response time for a task (fixed-point iteration)
 */
uint32_t an_response_time(pid32 pid);

/**
 * Compute interference from higher priority tasks
 */
uint32_t an_interference(pid32 pid, uint32_t interval);

/**
 * Check if task can meet its deadline
 */
bool an_is_schedulable(pid32 pid);

/**
 * Run full schedulability analysis
 */
bool an_analyze_schedulability(an_results_t *results);

/**
 * Compute system utilization
 */
double an_compute_utilization(void);

/**
 * Liu & Layland utilization bound
 */
double an_utilization_bound(uint32_t n);

/**
 * Check schedulability using utilization bound
 */
bool an_check_utilization_bound(void);

/**
 * Check schedulability using response time analysis
 */
bool an_check_response_time(void);

/**
 * Compare blocking times across protocols
 */
void an_compare_protocols(an_results_t *results);

/**
 * Recommend best protocol for system
 */
pi_protocol_t an_recommend_protocol(void);

/**
 * Analyze priority inversion scenarios
 */
uint32_t an_count_inversions(void);

/**
 * Compute slack time for a task
 */
int32_t an_slack_time(pid32 pid);

/**
 * Compute how much WCET can increase
 */
uint32_t an_wcet_slack(pid32 pid);

/**
 * Find critical task (closest to missing deadline)
 */
pid32 an_find_critical_task(void);

/**
 * Compute critical scaling factor
 */
double an_critical_scaling(void);

/**
 * Get analysis results
 */
void an_get_results(an_results_t *results);

/**
 * Print task analysis
 */
void an_print_task(pid32 pid);

/**
 * Print all tasks
 */
void an_print_all_tasks(void);

/**
 * Print resource analysis
 */
void an_print_resources(void);

/**
 * Print blocking analysis
 */
void an_print_blocking(void);

/**
 * Print schedulability report
 */
void an_print_report(void);

/**
 * Export analysis to CSV format
 */
pi_error_t an_export_csv(const char *filename);

/**
 * Get task by PID
 */
an_task_info_t *an_get_task(pid32 pid);

/**
 * Get resource by ID
 */
an_resource_info_t *an_get_resource(int32_t resource_id);

/**
 * Sort tasks by priority
 */
void an_sort_by_priority(pid32 *pids, uint32_t count);

/**
 * Find tasks using a resource
 */
uint32_t an_find_resource_users(int32_t resource_id, pid32 *users, uint32_t max);

/**
 * Ceiling function for time calculations
 */
uint32_t an_ceil_div(uint32_t a, uint32_t b);

#endif /* _ANALYSIS_H_ */
