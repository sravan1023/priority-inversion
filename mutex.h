/*
 * mutex.h - Mutex Abstraction with Priority Inversion Prevention
 *
 * Provides a high-level mutex interface that automatically handles
 * priority inversion using the configured protocol.
 */

#ifndef _MUTEX_H_
#define _MUTEX_H_

#include <stdint.h>
#include <stdbool.h>
#include "priority_inversion.h"

typedef enum mutex_type {
    MUTEX_NORMAL,               /* Non-recursive mutex */
    MUTEX_RECURSIVE,            /* Recursive mutex (same thread can lock multiple times) */
    MUTEX_ERRORCHECK,           /* Error checking mutex */
    MUTEX_ADAPTIVE,             /* Spin briefly before blocking */
} mutex_type_t;

typedef struct mutex_attr {
    mutex_type_t    type;               /* Mutex type */
    pi_protocol_t   protocol;           /* Priority protocol */
    uint32_t        ceiling;            /* Priority ceiling (0 = compute) */
    uint32_t        spin_count;         /* Spin iterations for adaptive */
    const char      *name;              /* Debug name */
} mutex_attr_t;

/* Default attributes */
#define MUTEX_ATTR_INIT { \
    .type = MUTEX_NORMAL, \
    .protocol = PI_PROTOCOL_INHERITANCE, \
    .ceiling = 0, \
    .spin_count = 100, \
    .name = NULL \
}

typedef struct mutex {
    int32_t         resource_id;        /* Underlying resource ID */
    mutex_type_t    type;               /* Mutex type */
    pi_protocol_t   protocol;           /* Protocol in use */
    uint32_t        spin_count;         /* Spin count for adaptive */
    bool            initialized;        /* Is mutex initialized */
    const char      *name;              /* Debug name */
    
    /* Statistics */
    uint64_t        lock_count;
    uint64_t        contention_count;
    uint64_t        spin_success;
    uint64_t        spin_fail;
} mutex_t;

/**
 * Initialize a mutex
 * 
 * @param mutex: Mutex to initialize
 * @param attr: Attributes (NULL for defaults)
 * 
 * Returns: PI_OK on success
 */
pi_error_t mutex_init(mutex_t *mutex, const mutex_attr_t *attr);

/**
 * Destroy a mutex
 * 
 * @param mutex: Mutex to destroy
 * 
 * Returns: PI_OK on success
 */
pi_error_t mutex_destroy(mutex_t *mutex);

/**
 * Lock a mutex (blocking)
 * 
 * @param mutex: Mutex to lock
 * 
 * Returns: PI_OK on success
 */
pi_error_t mutex_lock(mutex_t *mutex);

/**
 * Try to lock without blocking
 * 
 * @param mutex: Mutex to try
 * 
 * Returns: PI_OK if locked, PI_ERROR_RESOURCE_BUSY if not
 */
pi_error_t mutex_trylock(mutex_t *mutex);

/**
 * Lock with timeout
 * 
 * @param mutex: Mutex to lock
 * @param timeout: Maximum ticks to wait
 * 
 * Returns: PI_OK if locked, PI_ERROR_RESOURCE_BUSY on timeout
 */
pi_error_t mutex_timedlock(mutex_t *mutex, uint32_t timeout);

/**
 * Unlock a mutex
 * 
 * @param mutex: Mutex to unlock
 * 
 * Returns: PI_OK on success
 */
pi_error_t mutex_unlock(mutex_t *mutex);

/**
 * Get mutex owner
 * 
 * @param mutex: Mutex to query
 * 
 * Returns: Owner PID or PI_INVALID_PID
 */
pid32 mutex_get_owner(mutex_t *mutex);

/**
 * Check if mutex is locked
 * 
 * @param mutex: Mutex to query
 * 
 * Returns: true if locked
 */
bool mutex_is_locked(mutex_t *mutex);

/**
 * Print mutex statistics
 * 
 * @param mutex: Mutex to print
 */
void mutex_print_stats(mutex_t *mutex);

/* Static mutex initializer */
#define MUTEX_INITIALIZER { \
    .resource_id = -1, \
    .type = MUTEX_NORMAL, \
    .protocol = PI_PROTOCOL_INHERITANCE, \
    .initialized = false \
}

/* Lock guard (for use with cleanup attribute if available) */
#define MUTEX_LOCK_GUARD(m) \
    mutex_lock(m); \
    /* Use with __attribute__((cleanup(mutex_unlock_guard))) */

#endif /* _MUTEX_H_ */
