/*
 * analysis.c - Blocking Time Analysis Implementation
 * Implements worst-case blocking time computation and schedulability
 * analysis for real-time systems with priority inversion protocols.
 */

#include "analysis.h"
#include "../include/kernel.h"
#include "../include/process.h"
#include <string.h>

an_context_t analysis_context;

/**
 * Initialize analysis context
 */
pi_error_t an_init(const an_config_t *config)
{
    memset(&analysis_context, 0, sizeof(an_context_t));
    
    if (config) {
        memcpy(&analysis_context.config, config, sizeof(an_config_t));
    } else {
        /* Default configuration */
        analysis_context.config.protocol = PI_PROTOCOL_INHERITANCE;
        analysis_context.config.compute_response = true;
        analysis_context.config.compare_protocols = false;
        analysis_context.config.max_iterations = 100;
        analysis_context.config.convergence_threshold = 1;
    }
    
    analysis_context.initialized = true;
    return PI_OK;
}

/**
 * Reset analysis context
 */
void an_reset(void)
{
    an_config_t saved_config = analysis_context.config;
    memset(&analysis_context, 0, sizeof(an_context_t));
    analysis_context.config = saved_config;
    analysis_context.initialized = true;
}

/**
 * Configure analysis parameters
 */
pi_error_t an_configure(const an_config_t *config)
{
    if (config == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    memcpy(&analysis_context.config, config, sizeof(an_config_t));
    return PI_OK;
}

/**
 * Add task to analysis
 */
pi_error_t an_add_task(const an_task_params_t *params)
{
    if (params == NULL || !analysis_context.initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    if (analysis_context.task_count >= AN_MAX_TASKS) {
        return PI_ERROR_NO_MEMORY;
    }
    
    /* Check for duplicate */
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        if (analysis_context.tasks[i].params.pid == params->pid) {
            return PI_ERROR_INVALID_OPERATION;
        }
    }
    
    /* Add task */
    an_task_info_t *task = &analysis_context.tasks[analysis_context.task_count];
    memset(task, 0, sizeof(an_task_info_t));
    memcpy(&task->params, params, sizeof(an_task_params_t));
    task->params.active = true;
    
    /* Compute utilization */
    if (params->period > 0) {
        task->utilization = (double)params->wcet / params->period;
    }
    
    analysis_context.task_count++;
    return PI_OK;
}

/**
 * Remove task from analysis
 */
pi_error_t an_remove_task(pid32 pid)
{
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        if (analysis_context.tasks[i].params.pid == pid) {
            /* Shift remaining tasks */
            for (uint32_t j = i; j < analysis_context.task_count - 1; j++) {
                analysis_context.tasks[j] = analysis_context.tasks[j + 1];
            }
            analysis_context.task_count--;
            return PI_OK;
        }
    }
    
    return PI_ERROR_INVALID_PROCESS;
}

/**
 * Update task parameters
 */
pi_error_t an_update_task(pid32 pid, const an_task_params_t *params)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL || params == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    memcpy(&task->params, params, sizeof(an_task_params_t));
    
    if (params->period > 0) {
        task->utilization = (double)params->wcet / params->period;
    }
    
    return PI_OK;
}

/**
 * Add critical section to task
 */
pi_error_t an_add_critical_section(pid32 pid, int32_t resource_id,
                                    uint32_t duration, bool nested,
                                    int32_t outer_resource)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) {
        return PI_ERROR_INVALID_PROCESS;
    }
    
    if (task->cs_count >= AN_MAX_CRITICAL_SECTIONS) {
        return PI_ERROR_NO_MEMORY;
    }
    
    an_critical_section_t *cs = &task->cs[task->cs_count];
    cs->resource_id = resource_id;
    cs->duration = duration;
    cs->nested = nested;
    cs->outer_resource = outer_resource;
    
    task->cs_count++;
    
    /* Add task to resource user list */
    an_resource_info_t *res = an_get_resource(resource_id);
    if (res && res->user_count < AN_MAX_TASKS) {
        bool already_user = false;
        for (uint32_t i = 0; i < res->user_count; i++) {
            if (res->users[i] == pid) {
                already_user = true;
                break;
            }
        }
        if (!already_user) {
            res->users[res->user_count++] = pid;
        }
    }
    
    return PI_OK;
}

/**
 * Add resource to analysis
 */
pi_error_t an_add_resource(int32_t resource_id, pri16 ceiling,
                           uint32_t preemption_level)
{
    if (!analysis_context.initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    if (analysis_context.resource_count >= AN_MAX_RESOURCES) {
        return PI_ERROR_NO_MEMORY;
    }
    
    /* Check for duplicate */
    for (uint32_t i = 0; i < analysis_context.resource_count; i++) {
        if (analysis_context.resources[i].resource_id == resource_id) {
            return PI_ERROR_INVALID_OPERATION;
        }
    }
    
    an_resource_info_t *res = &analysis_context.resources[analysis_context.resource_count];
    memset(res, 0, sizeof(an_resource_info_t));
    res->resource_id = resource_id;
    res->ceiling = ceiling;
    res->preemption_level = preemption_level;
    
    analysis_context.resource_count++;
    return PI_OK;
}

/**
 * Remove resource from analysis
 */
pi_error_t an_remove_resource(int32_t resource_id)
{
    for (uint32_t i = 0; i < analysis_context.resource_count; i++) {
        if (analysis_context.resources[i].resource_id == resource_id) {
            /* Shift remaining resources */
            for (uint32_t j = i; j < analysis_context.resource_count - 1; j++) {
                analysis_context.resources[j] = analysis_context.resources[j + 1];
            }
            analysis_context.resource_count--;
            return PI_OK;
        }
    }
    
    return PI_ERROR_INVALID_RESOURCE;
}

/**
 * Compute resource ceiling from task access
 */
pri16 an_compute_ceiling(int32_t resource_id)
{
    pri16 ceiling = 0;  /* Lowest priority */
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *task = &analysis_context.tasks[i];
        
        for (uint32_t j = 0; j < task->cs_count; j++) {
            if (task->cs[j].resource_id == resource_id) {
                if (task->params.priority > ceiling) {
                    ceiling = task->params.priority;
                }
                break;
            }
        }
    }
    
    return ceiling;
}

/**
 * Compute SRP preemption level
 */
uint32_t an_compute_preemption_level(int32_t resource_id)
{
    uint32_t level = 0;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *task = &analysis_context.tasks[i];
        
        for (uint32_t j = 0; j < task->cs_count; j++) {
            if (task->cs[j].resource_id == resource_id) {
                if (task->params.preemption_level > level) {
                    level = task->params.preemption_level;
                }
                break;
            }
        }
    }
    
    return level;
}

/**
 * Compute blocking time for a task using Priority Inheritance
 *
 * With PIP, a task can be blocked at most once by each lower-priority
 * task that shares a resource, for the duration of the longest critical
 * section that blocks a higher priority task.
 */
uint32_t an_blocking_pip(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    uint32_t total_blocking = 0;
    
    /* For each lower-priority task */
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *other = &analysis_context.tasks[i];
        
        /* Skip self and higher/equal priority tasks */
        if (other->params.pid == pid || 
            other->params.priority >= task->params.priority) {
            continue;
        }
        
        /* Find longest critical section that can block task */
        uint32_t max_block = 0;
        
        for (uint32_t j = 0; j < other->cs_count; j++) {
            an_critical_section_t *cs = &other->cs[j];
            
            /* Check if task uses or can be blocked by this resource */
            an_resource_info_t *res = an_get_resource(cs->resource_id);
            if (res && res->ceiling >= task->params.priority) {
                if (cs->duration > max_block) {
                    max_block = cs->duration;
                }
            }
        }
        
        /* With PIP, can be blocked once per lower-priority task */
        total_blocking += max_block;
    }
    
    task->blocking_time = total_blocking;
    return total_blocking;
}

/**
 * Compute blocking time for a task using Priority Ceiling Protocol
 *
 * With PCP, a task can be blocked at most once, for the duration
 * of the longest critical section among all lower-priority tasks
 * that have ceiling >= task's priority.
 */
uint32_t an_blocking_pcp(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    uint32_t max_blocking = 0;
    
    /* Find maximum blocking from all lower-priority critical sections */
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *other = &analysis_context.tasks[i];
        
        /* Skip self and higher/equal priority tasks */
        if (other->params.pid == pid || 
            other->params.priority >= task->params.priority) {
            continue;
        }
        
        for (uint32_t j = 0; j < other->cs_count; j++) {
            an_critical_section_t *cs = &other->cs[j];
            an_resource_info_t *res = an_get_resource(cs->resource_id);
            
            /* Can block if resource ceiling >= task priority */
            if (res && res->ceiling >= task->params.priority) {
                if (cs->duration > max_blocking) {
                    max_blocking = cs->duration;
                }
            }
        }
    }
    
    task->blocking_time = max_blocking;
    return max_blocking;
}

/**
 * Compute blocking time for a task using Immediate PCP
 * Same bound as PCP
 */
uint32_t an_blocking_ipcp(pid32 pid)
{
    return an_blocking_pcp(pid);
}

/**
 * Compute blocking time for a task using Stack Resource Policy
 * With SRP, similar to PCP but uses preemption levels instead of priorities.
 */
uint32_t an_blocking_srp(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    uint32_t max_blocking = 0;
    
    /* Find maximum blocking from all tasks with lower preemption level */
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *other = &analysis_context.tasks[i];
        
        /* Skip self and tasks with higher/equal preemption level */
        if (other->params.pid == pid || 
            other->params.preemption_level >= task->params.preemption_level) {
            continue;
        }
        
        for (uint32_t j = 0; j < other->cs_count; j++) {
            an_critical_section_t *cs = &other->cs[j];
            an_resource_info_t *res = an_get_resource(cs->resource_id);
            
            /* Can block if resource preemption level >= task's level */
            if (res && res->preemption_level >= task->params.preemption_level) {
                if (cs->duration > max_blocking) {
                    max_blocking = cs->duration;
                }
            }
        }
    }
    
    task->blocking_time = max_blocking;
    return max_blocking;
}

/**
 * Compute blocking time based on configured protocol
 */
uint32_t an_blocking_time(pid32 pid)
{
    switch (analysis_context.config.protocol) {
    case PI_PROTOCOL_INHERITANCE:
        return an_blocking_pip(pid);
    case PI_PROTOCOL_CEILING:
        return an_blocking_pcp(pid);
    case PI_PROTOCOL_IMMEDIATE_CEILING:
        return an_blocking_ipcp(pid);
    case PI_PROTOCOL_SRP:
        return an_blocking_srp(pid);
    default:
        return an_blocking_pip(pid);
    }
}

/**
 * Compute maximum blocking by lower priority tasks
 */
uint32_t an_max_lower_blocking(pid32 pid)
{
    return an_blocking_time(pid);
}

/**
 * Compute interference from higher priority tasks
 */
uint32_t an_interference(pid32 pid, uint32_t interval)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    uint32_t interference = 0;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *other = &analysis_context.tasks[i];
        
        /* Only consider higher priority tasks */
        if (other->params.pid == pid || 
            other->params.priority <= task->params.priority) {
            continue;
        }
        
        /* Compute interference: ceiling(interval / period) * WCET */
        if (other->params.period > 0) {
            uint32_t activations = an_ceil_div(interval, other->params.period);
            interference += activations * other->params.wcet;
        }
    }
    
    return interference;
}

/**
 * Compute response time for a task 
 */
uint32_t an_response_time(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    uint32_t blocking = an_blocking_time(pid);
    uint32_t wcet = task->params.wcet;
    
    /* Initial estimate */
    uint32_t r = wcet + blocking;
    
    /* Fixed-point iteration */
    for (uint32_t iter = 0; iter < analysis_context.config.max_iterations; iter++) {
        uint32_t interference = an_interference(pid, r);
        uint32_t new_r = wcet + blocking + interference;
        
        /* Check for convergence */
        if (new_r == r) {
            task->response_time = r;
            return r;
        }
        
        /* Check for deadline miss (iteration diverging) */
        if (new_r > task->params.deadline) {
            task->response_time = new_r;
            task->schedulable = false;
            return new_r;
        }
        
        r = new_r;
    }
    
    /* Did not converge */
    task->response_time = r;
    return r;
}

/**
 * Check if task can meet its deadline
 */
bool an_is_schedulable(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return false;
    
    uint32_t response = an_response_time(pid);
    task->schedulable = (response <= task->params.deadline);
    return task->schedulable;
}

/**
 * Run full schedulability analysis
 */
bool an_analyze_schedulability(an_results_t *results)
{
    if (results == NULL) {
        results = &analysis_context.results;
    }
    
    memset(results, 0, sizeof(an_results_t));
    
    bool all_schedulable = true;
    uint32_t total_blocking = 0;
    
    /* Analyze each task */
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *task = &analysis_context.tasks[i];
        pid32 pid = task->params.pid;
        
        /* Compute blocking time */
        results->blocking_times[i] = an_blocking_time(pid);
        total_blocking += results->blocking_times[i];
        
        /* Compute response time if configured */
        if (analysis_context.config.compute_response) {
            results->response_times[i] = an_response_time(pid);
        }
        
        /* Check schedulability */
        results->task_schedulable[i] = an_is_schedulable(pid);
        if (!results->task_schedulable[i]) {
            all_schedulable = false;
        }
        
        /* Track maximums */
        if (results->blocking_times[i] > results->max_blocking) {
            results->max_blocking = results->blocking_times[i];
        }
        if (results->response_times[i] > results->max_response) {
            results->max_response = results->response_times[i];
        }
    }
    
    /* Compute averages */
    if (analysis_context.task_count > 0) {
        results->avg_blocking = total_blocking / analysis_context.task_count;
    }
    
    /* Compute utilization */
    results->total_utilization = an_compute_utilization();
    
    /* Compare protocols if configured */
    if (analysis_context.config.compare_protocols) {
        an_compare_protocols(results);
    }
    
    results->system_schedulable = all_schedulable;
    memcpy(&analysis_context.results, results, sizeof(an_results_t));
    
    return all_schedulable;
}

/**
 * Compute system utilization
 */
double an_compute_utilization(void)
{
    double total = 0.0;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        total += analysis_context.tasks[i].utilization;
    }
    
    return total;
}

/**
 * Liu & Layland utilization bound: n * (2^(1/n) - 1)
 */
double an_utilization_bound(uint32_t n)
{
    if (n == 0) return 0.0;
    if (n == 1) return 1.0;
    
    /* Compute 2^(1/n) - 1 */
    /* For large n, approaches ln(2) ≈ 0.693 */
    double result = n;
    
    /* Simple approximation: n * (2^(1/n) - 1) */
    /* For n=2: 2*(sqrt(2)-1) ≈ 0.828 */
    /* For n=3: 3*(2^0.333-1) ≈ 0.779 */
    /* For large n: approaches ln(2) ≈ 0.693 */
    
    /* Use lookup table for common values */
    static const double bounds[] = {
        1.000,  /* n=1 */
        0.828,  /* n=2 */
        0.779,  /* n=3 */
        0.756,  /* n=4 */
        0.743,  /* n=5 */
        0.734,  /* n=6 */
        0.728,  /* n=7 */
        0.724,  /* n=8 */
        0.720,  /* n=9 */
        0.717   /* n=10 */
    };
    
    if (n <= 10) {
        return bounds[n - 1];
    }
    
    /* For larger n, use ln(2) */
    return 0.693;
}

/**
 * Check schedulability using utilization bound
 */
bool an_check_utilization_bound(void)
{
    double u = an_compute_utilization();
    double bound = an_utilization_bound(analysis_context.task_count);
    return u <= bound;
}

/**
 * Check schedulability using response time analysis
 */
bool an_check_response_time(void)
{
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        if (!an_is_schedulable(analysis_context.tasks[i].params.pid)) {
            return false;
        }
    }
    return true;
}

/**
 * Compare blocking times across protocols
 */
void an_compare_protocols(an_results_t *results)
{
    pi_protocol_t original = analysis_context.config.protocol;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        pid32 pid = analysis_context.tasks[i].params.pid;
        
        results->pip_blocking[i] = an_blocking_pip(pid);
        results->pcp_blocking[i] = an_blocking_pcp(pid);
        results->srp_blocking[i] = an_blocking_srp(pid);
    }
    
    analysis_context.config.protocol = original;
}

/**
 * Recommend best protocol for system
 */
pi_protocol_t an_recommend_protocol(void)
{
    an_results_t results;
    an_compare_protocols(&results);
    
    uint32_t pip_total = 0, pcp_total = 0, srp_total = 0;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        pip_total += results.pip_blocking[i];
        pcp_total += results.pcp_blocking[i];
        srp_total += results.srp_blocking[i];
    }
    
    /* Choose protocol with minimum total blocking */
    if (pcp_total <= pip_total && pcp_total <= srp_total) {
        return PI_PROTOCOL_CEILING;
    } else if (srp_total <= pip_total) {
        return PI_PROTOCOL_SRP;
    } else {
        return PI_PROTOCOL_INHERITANCE;
    }
}

/**
 * Count priority inversion scenarios
 */
uint32_t an_count_inversions(void)
{
    uint32_t count = 0;
    
    /* Count shared resources between tasks of different priorities */
    for (uint32_t r = 0; r < analysis_context.resource_count; r++) {
        an_resource_info_t *res = &analysis_context.resources[r];
        
        if (res->user_count > 1) {
            /* Check for priority differences among users */
            for (uint32_t i = 0; i < res->user_count; i++) {
                for (uint32_t j = i + 1; j < res->user_count; j++) {
                    an_task_info_t *t1 = an_get_task(res->users[i]);
                    an_task_info_t *t2 = an_get_task(res->users[j]);
                    
                    if (t1 && t2 && t1->params.priority != t2->params.priority) {
                        count++;
                    }
                }
            }
        }
    }
    
    return count;
}

/**
 * Compute slack time for a task
 */
int32_t an_slack_time(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    uint32_t response = an_response_time(pid);
    return (int32_t)task->params.deadline - (int32_t)response;
}

/**
 * Compute how much WCET can increase
 */
uint32_t an_wcet_slack(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) return 0;
    
    int32_t slack = an_slack_time(pid);
    if (slack <= 0) return 0;
    
    /* WCET can increase by approximately slack time */
    return (uint32_t)slack;
}

/**
 * Find critical task (closest to missing deadline)
 */
pid32 an_find_critical_task(void)
{
    pid32 critical = PI_INVALID_PID;
    int32_t min_slack = MAXINT32;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        pid32 pid = analysis_context.tasks[i].params.pid;
        int32_t slack = an_slack_time(pid);
        
        if (slack < min_slack) {
            min_slack = slack;
            critical = pid;
        }
    }
    
    return critical;
}

/**
 * Compute critical scaling factor
 */
double an_critical_scaling(void)
{
    /* Find minimum ratio of deadline/response across tasks */
    double min_ratio = 1e10;
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *task = &analysis_context.tasks[i];
        
        if (task->response_time > 0) {
            double ratio = (double)task->params.deadline / task->response_time;
            if (ratio < min_ratio) {
                min_ratio = ratio;
            }
        }
    }
    
    return min_ratio;
}

/**
 * Get analysis results
 */
void an_get_results(an_results_t *results)
{
    if (results) {
        memcpy(results, &analysis_context.results, sizeof(an_results_t));
    }
}

/**
 * Print task analysis
 */
void an_print_task(pid32 pid)
{
    an_task_info_t *task = an_get_task(pid);
    if (task == NULL) {
        kprintf("Task %d not found\n", pid);
        return;
    }
    
    kprintf("\nTask %d Analysis:\n", pid);
    kprintf("  Priority:     %d\n", task->params.priority);
    kprintf("  Period:       %u us\n", task->params.period);
    kprintf("  Deadline:     %u us\n", task->params.deadline);
    kprintf("  WCET:         %u us\n", task->params.wcet);
    kprintf("  Utilization:  %.3f\n", task->utilization);
    kprintf("  Blocking:     %u us\n", task->blocking_time);
    kprintf("  Response:     %u us\n", task->response_time);
    kprintf("  Slack:        %d us\n", an_slack_time(pid));
    kprintf("  Schedulable:  %s\n", task->schedulable ? "YES" : "NO");
    
    if (task->cs_count > 0) {
        kprintf("  Critical Sections:\n");
        for (uint32_t i = 0; i < task->cs_count; i++) {
            kprintf("    R%d: %u us%s\n",
                    task->cs[i].resource_id,
                    task->cs[i].duration,
                    task->cs[i].nested ? " (nested)" : "");
        }
    }
}

/**
 * Print all tasks
 */
void an_print_all_tasks(void)
{
    kprintf("\n=== Task Analysis Summary ===\n");
    kprintf("%-5s %-5s %-8s %-8s %-8s %-8s %-8s %-6s\n",
            "PID", "Pri", "Period", "WCET", "Blocking", "Response", "Deadline", "OK?");
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *task = &analysis_context.tasks[i];
        kprintf("%-5d %-5d %-8u %-8u %-8u %-8u %-8u %-6s\n",
                task->params.pid,
                task->params.priority,
                task->params.period,
                task->params.wcet,
                task->blocking_time,
                task->response_time,
                task->params.deadline,
                task->schedulable ? "Yes" : "No");
    }
}

/**
 * Print resource analysis
 */
void an_print_resources(void)
{
    kprintf("\n=== Resource Analysis ===\n");
    
    for (uint32_t i = 0; i < analysis_context.resource_count; i++) {
        an_resource_info_t *res = &analysis_context.resources[i];
        kprintf("Resource %d: ceiling=%d, preempt_level=%u, max_hold=%u\n",
                res->resource_id,
                res->ceiling,
                res->preemption_level,
                res->max_hold_time);
        
        if (res->user_count > 0) {
            kprintf("  Users: ");
            for (uint32_t j = 0; j < res->user_count; j++) {
                kprintf("T%d ", res->users[j]);
            }
            kprintf("\n");
        }
    }
}

/**
 * Print blocking analysis
 */
void an_print_blocking(void)
{
    kprintf("\n=== Blocking Time Analysis ===\n");
    
    const char *proto_name;
    switch (analysis_context.config.protocol) {
    case PI_PROTOCOL_INHERITANCE: proto_name = "PIP"; break;
    case PI_PROTOCOL_CEILING: proto_name = "PCP"; break;
    case PI_PROTOCOL_IMMEDIATE_CEILING: proto_name = "IPCP"; break;
    case PI_PROTOCOL_SRP: proto_name = "SRP"; break;
    default: proto_name = "Unknown"; break;
    }
    
    kprintf("Protocol: %s\n\n", proto_name);
    kprintf("%-5s %-10s %-10s %-10s\n", "Task", "PIP", "PCP", "SRP");
    kprintf("--------------------------------------\n");
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        pid32 pid = analysis_context.tasks[i].params.pid;
        kprintf("T%-4d %-10u %-10u %-10u\n",
                pid,
                an_blocking_pip(pid),
                an_blocking_pcp(pid),
                an_blocking_srp(pid));
    }
}

/**
 * Print schedulability report
 */
void an_print_report(void)
{
    an_results_t results;
    an_analyze_schedulability(&results);
    
    kprintf("\n");
    kprintf("           SCHEDULABILITY ANALYSIS REPORT           \n");
    
    kprintf("\nSystem Summary:\n");
    kprintf("  Tasks:           %u\n", analysis_context.task_count);
    kprintf("  Resources:       %u\n", analysis_context.resource_count);
    kprintf("  Utilization:     %.3f (%.1f%%)\n",
            results.total_utilization, results.total_utilization * 100);
    kprintf("  Util Bound:      %.3f\n", 
            an_utilization_bound(analysis_context.task_count));
    kprintf("  Max Blocking:    %u us\n", results.max_blocking);
    kprintf("  Avg Blocking:    %u us\n", results.avg_blocking);
    kprintf("  Max Response:    %u us\n", results.max_response);
    
    kprintf("\nSchedulability:\n");
    kprintf("  Util Bound Test: %s\n", 
            an_check_utilization_bound() ? "PASS" : "FAIL");
    kprintf("  Response Time:   %s\n",
            results.system_schedulable ? "PASS" : "FAIL");
    
    kprintf("\nRecommended Protocol: ");
    switch (an_recommend_protocol()) {
    case PI_PROTOCOL_INHERITANCE: kprintf("Priority Inheritance\n"); break;
    case PI_PROTOCOL_CEILING: kprintf("Priority Ceiling\n"); break;
    case PI_PROTOCOL_SRP: kprintf("Stack Resource Policy\n"); break;
    default: kprintf("Unknown\n"); break;
    }
    
    an_print_all_tasks();
    
    if (!results.system_schedulable) {
        kprintf("\nWARNING: System is NOT schedulable!\n");
        kprintf("Critical task: T%d\n", an_find_critical_task());
    }
    
    kprintf("\n====================================================\n");
}

/**
 * Export analysis to CSV format
 */
pi_error_t an_export_csv(const char *filename)
{
    /* Would write to file in real implementation */
    kprintf("CSV export to '%s' (simulated):\n", filename);
    kprintf("pid,priority,period,wcet,deadline,blocking,response,schedulable\n");
    
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        an_task_info_t *task = &analysis_context.tasks[i];
        kprintf("%d,%d,%u,%u,%u,%u,%u,%d\n",
                task->params.pid,
                task->params.priority,
                task->params.period,
                task->params.wcet,
                task->params.deadline,
                task->blocking_time,
                task->response_time,
                task->schedulable ? 1 : 0);
    }
    
    return PI_OK;
}

/**
 * Get task by PID
 */
an_task_info_t *an_get_task(pid32 pid)
{
    for (uint32_t i = 0; i < analysis_context.task_count; i++) {
        if (analysis_context.tasks[i].params.pid == pid) {
            return &analysis_context.tasks[i];
        }
    }
    return NULL;
}

/**
 * Get resource by ID
 */
an_resource_info_t *an_get_resource(int32_t resource_id)
{
    for (uint32_t i = 0; i < analysis_context.resource_count; i++) {
        if (analysis_context.resources[i].resource_id == resource_id) {
            return &analysis_context.resources[i];
        }
    }
    return NULL;
}

/**
 * Sort tasks by priority (descending - highest first)
 */
void an_sort_by_priority(pid32 *pids, uint32_t count)
{
    /* Simple bubble sort */
    for (uint32_t i = 0; i < count - 1; i++) {
        for (uint32_t j = 0; j < count - i - 1; j++) {
            an_task_info_t *t1 = an_get_task(pids[j]);
            an_task_info_t *t2 = an_get_task(pids[j + 1]);
            
            if (t1 && t2 && t1->params.priority < t2->params.priority) {
                pid32 temp = pids[j];
                pids[j] = pids[j + 1];
                pids[j + 1] = temp;
            }
        }
    }
}

/**
 * Find tasks using a resource
 */
uint32_t an_find_resource_users(int32_t resource_id, pid32 *users, uint32_t max)
{
    an_resource_info_t *res = an_get_resource(resource_id);
    if (res == NULL) return 0;
    
    uint32_t count = (res->user_count < max) ? res->user_count : max;
    for (uint32_t i = 0; i < count; i++) {
        users[i] = res->users[i];
    }
    return count;
}

/**
 * Ceiling division: ceil(a/b)
 */
uint32_t an_ceil_div(uint32_t a, uint32_t b)
{
    if (b == 0) return 0;
    return (a + b - 1) / b;
}
