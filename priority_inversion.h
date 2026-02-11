/*
 * priority_inversion.h - Priority Inversion Prevention for Xinu
 *
 * Defines interfaces for preventing priority inversion in real-time
 * and priority-based scheduling systems. Implements multiple protocols:
 * - Priority Inheritance Protocol (PIP)
 * - Priority Ceiling Protocol (PCP)
 * - Immediate Priority Ceiling Protocol (IPCP)
 * - Stack Resource Policy (SRP)
 */

#ifndef _PRIORITY_INVERSION_H_
#define _PRIORITY_INVERSION_H_

#include <stdint.h>
#include <stdbool.h>
#include "../include/kernel.h"
#include "../include/process.h"

/* Maximum number of mutex/semaphore resources */
#ifndef PI_MAX_RESOURCES
#define PI_MAX_RESOURCES        64
#endif

/* Maximum number of processes */
#ifndef PI_MAX_PROCESSES
#define PI_MAX_PROCESSES        256
#endif

/* Maximum resources a single process can hold */
#define PI_MAX_HELD_RESOURCES   16

/* Maximum nested resource acquisitions */
#define PI_MAX_NESTING_DEPTH    8

/* Priority range */
#define PI_PRIORITY_MIN         0
#define PI_PRIORITY_MAX         255

/* Invalid identifiers */
#define PI_INVALID_PID          (-1)
#define PI_INVALID_RESOURCE     (-1)

typedef enum pi_error {
    PI_OK = 0,                      /* Success */
    PI_ERROR_INVALID_RESOURCE,      /* Invalid resource ID */
    PI_ERROR_INVALID_PROCESS,       /* Invalid process ID */
    PI_ERROR_RESOURCE_BUSY,         /* Resource already held */
    PI_ERROR_NOT_OWNER,             /* Process doesn't own resource */
    PI_ERROR_DEADLOCK,              /* Deadlock detected */
    PI_ERROR_NESTING_OVERFLOW,      /* Too many nested acquisitions */
    PI_ERROR_CEILING_VIOLATION,     /* Priority ceiling violation */
    PI_ERROR_NO_MEMORY,             /* Out of memory/resources */
    PI_ERROR_NOT_INITIALIZED,       /* System not initialized */
} pi_error_t;

typedef enum pi_protocol {
    PI_PROTOCOL_NONE,               /* No protocol (for comparison) */
    PI_PROTOCOL_INHERITANCE,        /* Priority Inheritance Protocol */
    PI_PROTOCOL_CEILING,            /* Priority Ceiling Protocol */
    PI_PROTOCOL_IMMEDIATE_CEILING,  /* Immediate Priority Ceiling */
    PI_PROTOCOL_SRP,                /* Stack Resource Policy */
} pi_protocol_t;

typedef enum pi_resource_type {
    PI_RESOURCE_MUTEX,              /* Mutual exclusion (binary) */
    PI_RESOURCE_SEMAPHORE,          /* Counting semaphore */
    PI_RESOURCE_RWLOCK,             /* Read-write lock */
} pi_resource_type_t;

typedef struct pi_wait_entry {
    pid32   pid;                    /* Waiting process */
    uint32_t priority;              /* Priority when started waiting */
    uint64_t wait_start;            /* When wait started (ticks) */
    struct pi_wait_entry *next;     /* Next in queue */
} pi_wait_entry_t;

typedef struct pi_resource {
    int32_t             id;             /* Resource identifier */
    pi_resource_type_t  type;           /* Resource type */
    pi_protocol_t       protocol;       /* Protection protocol */
    
    /* State */
    int32_t     count;                  /* Current count (semaphore) */
    int32_t     max_count;              /* Maximum count */
    pid32       owner;                  /* Current owner (-1 if free) */
    uint32_t    lock_count;             /* Recursive lock count */
    
    /* Priority Ceiling */
    uint32_t    ceiling;                /* Priority ceiling */
    uint32_t    computed_ceiling;       /* Computed ceiling (max of accessors) */
    
    /* Wait queue (sorted by priority, descending) */
    pi_wait_entry_t *wait_queue;
    uint32_t    wait_count;
    
    /* Statistics */
    uint64_t    acquisitions;           /* Total acquisitions */
    uint64_t    contentions;            /* Times waited for resource */
    uint64_t    total_hold_time;        /* Total time held */
    uint64_t    max_hold_time;          /* Maximum hold time */
    uint64_t    inheritance_count;      /* Priority inheritance events */
    uint64_t    blocking_time;          /* Total blocking time caused */
    
    /* SRP specific */
    uint32_t    preemption_level;       /* For SRP */
    
    /* Bookkeeping */
    uint64_t    acquire_time;           /* When current acquisition started */
    bool        initialized;            /* Is resource initialized */
    const char  *name;                  /* Resource name (debug) */
} pi_resource_t;

typedef struct pi_process_info {
    pid32       pid;                    /* Process ID */
    uint32_t    base_priority;          /* Original base priority */
    uint32_t    current_priority;       /* Current effective priority */
    uint32_t    inherited_priority;     /* Highest inherited priority */
    
    /* Resources held by this process */
    int32_t     held_resources[PI_MAX_HELD_RESOURCES];
    uint32_t    held_count;
    
    /* Resource waiting for */
    int32_t     waiting_for;            /* Resource ID waiting for (-1 if none) */
    
    /* Priority stack for nested ceiling */
    uint32_t    priority_stack[PI_MAX_NESTING_DEPTH];
    uint32_t    priority_stack_top;
    
    /* SRP preemption level */
    uint32_t    preemption_level;
    
    /* Statistics */
    uint64_t    total_blocked_time;
    uint64_t    inheritance_received;
    uint64_t    blocking_caused;
    
    bool        active;
} pi_process_info_t;

typedef struct pi_system_state {
    /* Global state */
    bool            initialized;
    pi_protocol_t   default_protocol;
    uint64_t        system_time;
    
    /* System ceiling (for IPCP/SRP) */
    uint32_t        system_ceiling;
    
    /* Statistics */
    uint64_t        total_inversions_prevented;
    uint64_t        total_inheritance_events;
    uint64_t        total_ceiling_raises;
    uint64_t        deadlocks_detected;
    
    /* Configuration */
    bool            deadlock_detection;
    bool            statistics_enabled;
    bool            debug_enabled;
} pi_system_state_t;


typedef struct pi_inheritance_chain {
    pid32       chain[PI_MAX_NESTING_DEPTH];
    uint32_t    priorities[PI_MAX_NESTING_DEPTH];
    int32_t     resources[PI_MAX_NESTING_DEPTH];
    uint32_t    length;
} pi_inheritance_chain_t;

typedef struct pi_stats {
    uint64_t    inversions_prevented;
    uint64_t    inheritance_events;
    uint64_t    ceiling_raises;
    uint64_t    deadlocks_detected;
    uint64_t    total_blocking_time;
    uint64_t    max_blocking_time;
    uint64_t    avg_blocking_time;
    uint32_t    max_chain_length;
    double      inversion_rate;
} pi_stats_t;

/**
 * Initialize priority inversion prevention system
 * 
 * @param protocol: Default protocol to use
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_init(pi_protocol_t protocol);

/**
 * Shutdown priority inversion system
 */
void pi_shutdown(void);

/**
 * Set default protocol for new resources
 * 
 * @param protocol: Protocol to use
 */
void pi_set_default_protocol(pi_protocol_t protocol);

/**
 * Get current default protocol
 */
pi_protocol_t pi_get_default_protocol(void);

/**
 * Create/initialize a resource
 * 
 * @param id: Resource identifier
 * @param type: Resource type (mutex, semaphore, rwlock)
 * @param protocol: Protection protocol
 * @param initial_count: Initial count (1 for mutex)
 * @param ceiling: Priority ceiling (0 to compute automatically)
 * @param name: Resource name for debugging
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_resource_init(int32_t id, pi_resource_type_t type,
                            pi_protocol_t protocol, int32_t initial_count,
                            uint32_t ceiling, const char *name);

/**
 * Destroy a resource
 * 
 * @param id: Resource identifier
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_resource_destroy(int32_t id);

/**
 * Set resource ceiling priority
 * 
 * @param id: Resource identifier
 * @param ceiling: New ceiling priority
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_resource_set_ceiling(int32_t id, uint32_t ceiling);

/**
 * Get resource ceiling priority
 * 
 * @param id: Resource identifier
 * 
 * Returns: Ceiling priority
 */
uint32_t pi_resource_get_ceiling(int32_t id);

/**
 * Register process as potential accessor of resource
 * (Used for automatic ceiling computation)
 * 
 * @param resource_id: Resource identifier
 * @param pid: Process that may access resource
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_resource_register_accessor(int32_t resource_id, pid32 pid);

/**
 * Acquire (lock) a resource
 * 
 * @param id: Resource identifier
 * 
 * Returns: PI_OK on success, error code on failure
 */
pi_error_t pi_acquire(int32_t id);

/**
 * Try to acquire a resource without blocking
 * 
 * @param id: Resource identifier
 * 
 * Returns: PI_OK if acquired, PI_ERROR_RESOURCE_BUSY if not available
 */
pi_error_t pi_try_acquire(int32_t id);

/**
 * Acquire with timeout
 * 
 * @param id: Resource identifier
 * @param timeout: Maximum ticks to wait
 * 
 * Returns: PI_OK if acquired, PI_ERROR_RESOURCE_BUSY on timeout
 */
pi_error_t pi_acquire_timeout(int32_t id, uint32_t timeout);

/**
 * Release (unlock) a resource
 * 
 * @param id: Resource identifier
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_release(int32_t id);

/**
 * Register a process with the PI system
 * 
 * @param pid: Process ID
 * @param priority: Base priority
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_register_process(pid32 pid, uint32_t priority);

/**
 * Unregister a process
 * 
 * @param pid: Process ID
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_unregister_process(pid32 pid);

/**
 * Update process base priority
 * 
 * @param pid: Process ID
 * @param priority: New base priority
 * 
 * Returns: PI_OK on success
 */
pi_error_t pi_set_base_priority(pid32 pid, uint32_t priority);

/**
 * Get process current effective priority
 * 
 * @param pid: Process ID
 * 
 * Returns: Effective priority
 */
uint32_t pi_get_effective_priority(pid32 pid);

/**
 * Get process base priority
 * 
 * @param pid: Process ID
 * 
 * Returns: Base priority
 */
uint32_t pi_get_base_priority(pid32 pid);

/**
 * Enable/disable deadlock detection
 * 
 * @param enable: true to enable
 */
void pi_deadlock_detection_enable(bool enable);

/**
 * Check for potential deadlock
 * 
 * @param pid: Process attempting acquisition
 * @param resource_id: Resource being requested
 * 
 * Returns: true if deadlock would occur
 */
bool pi_check_deadlock(pid32 pid, int32_t resource_id);

/**
 * Get deadlock chain if detected
 * 
 * @param chain: Output chain structure
 * 
 * Returns: true if deadlock exists
 */
bool pi_get_deadlock_chain(pi_inheritance_chain_t *chain);

/**
 * Timer tick handler - call from timer interrupt
 */
void pi_tick(void);

/**
 * Get current system time
 */
uint64_t pi_get_time(void);

/**
 * Get system statistics
 * 
 * @param stats: Output structure
 */
void pi_get_stats(pi_stats_t *stats);

/**
 * Reset statistics
 */
void pi_reset_stats(void);

/**
 * Print statistics
 */
void pi_print_stats(void);

/**
 * Get resource statistics
 * 
 * @param id: Resource identifier
 * @param acquisitions: Output acquisitions count
 * @param contentions: Output contentions count
 * @param avg_hold: Output average hold time
 */
void pi_get_resource_stats(int32_t id, uint64_t *acquisitions,
                           uint64_t *contentions, uint64_t *avg_hold);

/**
 * Enable/disable debug output
 * 
 * @param enable: true to enable
 */
void pi_debug_enable(bool enable);

/**
 * Print resource state
 * 
 * @param id: Resource identifier
 */
void pi_print_resource(int32_t id);

/**
 * Print all resources
 */
void pi_print_all_resources(void);

/**
 * Print process state
 * 
 * @param pid: Process ID
 */
void pi_print_process(pid32 pid);

/**
 * Print inheritance chain
 * 
 * @param chain: Chain to print
 */
void pi_print_chain(pi_inheritance_chain_t *chain);

/**
 * Validate system state
 * 
 * Returns: true if consistent
 */
bool pi_validate(void);

/**
 * Get inheritance chain from a process
 * 
 * @param pid: Starting process
 * @param chain: Output chain
 * 
 * Returns: Chain length
 */
uint32_t pi_get_inheritance_chain(pid32 pid, pi_inheritance_chain_t *chain);

/* Initialize a mutex with inheritance protocol */
#define PI_MUTEX_INIT(id, name) \
    pi_resource_init(id, PI_RESOURCE_MUTEX, PI_PROTOCOL_INHERITANCE, 1, 0, name)

/* Initialize a mutex with ceiling protocol */
#define PI_MUTEX_CEILING_INIT(id, ceiling, name) \
    pi_resource_init(id, PI_RESOURCE_MUTEX, PI_PROTOCOL_CEILING, 1, ceiling, name)

/* Initialize a semaphore */
#define PI_SEM_INIT(id, count, name) \
    pi_resource_init(id, PI_RESOURCE_SEMAPHORE, PI_PROTOCOL_INHERITANCE, count, 0, name)

/* Lock/unlock macros */
#define PI_LOCK(id)     pi_acquire(id)
#define PI_UNLOCK(id)   pi_release(id)
#define PI_TRYLOCK(id)  pi_try_acquire(id)

#endif /* _PRIORITY_INVERSION_H_ */


