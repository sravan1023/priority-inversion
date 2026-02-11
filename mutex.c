/*
 * mutex.c - Mutex Implementation with Priority Inversion Prevention
 *
 * Provides a user-friendly mutex abstraction that handles priority
 * inversion automatically using the underlying protocol mechanisms.
 */

#include "mutex.h"
#include "priority_inversion.h"
#include "../include/kernel.h"
#include "../include/process.h"
#include "../include/interrupts.h"
#include <string.h>

/* Simple resource ID allocator */
static int32_t next_resource_id = 0;
static bool resource_used[PI_MAX_RESOURCES];

static int32_t alloc_resource_id(void)
{
    for (int i = 0; i < PI_MAX_RESOURCES; i++) {
        int32_t id = (next_resource_id + i) % PI_MAX_RESOURCES;
        if (!resource_used[id]) {
            resource_used[id] = true;
            next_resource_id = (id + 1) % PI_MAX_RESOURCES;
            return id;
        }
    }
    return -1;
}

static void free_resource_id(int32_t id)
{
    if (id >= 0 && id < PI_MAX_RESOURCES) {
        resource_used[id] = false;
    }
}

/**
 * Initialize a mutex
 */
pi_error_t mutex_init(mutex_t *mutex, const mutex_attr_t *attr)
{
    if (mutex == NULL) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    /* Use defaults if no attributes */
    mutex_attr_t default_attr = {
        .type = MUTEX_NORMAL,
        .protocol = PI_PROTOCOL_INHERITANCE,
        .ceiling = 0,
        .spin_count = 100,
        .name = NULL
    };
    
    if (attr == NULL) {
        attr = &default_attr;
    }
    
    /* Allocate resource ID */
    int32_t id = alloc_resource_id();
    if (id < 0) {
        return PI_ERROR_NO_MEMORY;
    }
    
    /* Initialize underlying resource */
    pi_error_t err = pi_resource_init(id, PI_RESOURCE_MUTEX,
                                      attr->protocol, 1,
                                      attr->ceiling, attr->name);
    if (err != PI_OK) {
        free_resource_id(id);
        return err;
    }
    
    /* Initialize mutex structure */
    mutex->resource_id = id;
    mutex->type = attr->type;
    mutex->protocol = attr->protocol;
    mutex->spin_count = attr->spin_count;
    mutex->name = attr->name;
    mutex->lock_count = 0;
    mutex->contention_count = 0;
    mutex->spin_success = 0;
    mutex->spin_fail = 0;
    mutex->initialized = true;
    
    return PI_OK;
}

/**
 * Destroy a mutex
 */
pi_error_t mutex_destroy(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pi_error_t err = pi_resource_destroy(mutex->resource_id);
    if (err != PI_OK) {
        return err;
    }
    
    free_resource_id(mutex->resource_id);
    mutex->initialized = false;
    
    return PI_OK;
}

/**
 * Lock a mutex (blocking)
 */
pi_error_t mutex_lock(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pi_error_t result;
    
    /* For adaptive mutex, try spinning first */
    if (mutex->type == MUTEX_ADAPTIVE) {
        for (uint32_t i = 0; i < mutex->spin_count; i++) {
            result = pi_try_acquire(mutex->resource_id);
            if (result == PI_OK) {
                mutex->spin_success++;
                mutex->lock_count++;
                return PI_OK;
            }
            /* Spin yield - just loop */
        }
        mutex->spin_fail++;
    }
    
    /* Regular blocking acquire */
    result = pi_acquire(mutex->resource_id);
    
    if (result == PI_OK) {
        mutex->lock_count++;
    } else if (result == PI_ERROR_RESOURCE_BUSY) {
        mutex->contention_count++;
        /* This shouldn't happen with blocking acquire */
    }
    
    return result;
}

/**
 * Try to lock without blocking
 */
pi_error_t mutex_trylock(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pi_error_t result = pi_try_acquire(mutex->resource_id);
    
    if (result == PI_OK) {
        mutex->lock_count++;
    } else if (result == PI_ERROR_RESOURCE_BUSY) {
        mutex->contention_count++;
    }
    
    return result;
}

/**
 * Lock with timeout
 */
pi_error_t mutex_timedlock(mutex_t *mutex, uint32_t timeout)
{
    if (mutex == NULL || !mutex->initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    pi_error_t result = pi_acquire_timeout(mutex->resource_id, timeout);
    
    if (result == PI_OK) {
        mutex->lock_count++;
    } else if (result == PI_ERROR_RESOURCE_BUSY) {
        mutex->contention_count++;
    }
    
    return result;
}

/**
 * Unlock a mutex
 */
pi_error_t mutex_unlock(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return PI_ERROR_INVALID_RESOURCE;
    }
    
    return pi_release(mutex->resource_id);
}

/**
 * Get mutex owner
 */
pid32 mutex_get_owner(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return PI_INVALID_PID;
    }
    
    /* Need to query the resource directly */
    /* This would require adding a function to priority_inversion.c */
    /* For now, return -1 */
    return PI_INVALID_PID;
}

/**
 * Check if mutex is locked
 */
bool mutex_is_locked(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        return false;
    }
    
    /* Try to acquire - if fails, it's locked */
    pi_error_t result = pi_try_acquire(mutex->resource_id);
    if (result == PI_OK) {
        /* We got it - release and return false */
        pi_release(mutex->resource_id);
        return false;
    }
    return true;
}

/**
 * Print mutex statistics
 */
void mutex_print_stats(mutex_t *mutex)
{
    if (mutex == NULL || !mutex->initialized) {
        kprintf("Mutex: not initialized\n");
        return;
    }
    
    const char *type_names[] = {"NORMAL", "RECURSIVE", "ERRORCHECK", "ADAPTIVE"};
    const char *proto_names[] = {"NONE", "INHERITANCE", "CEILING", "IMMED_CEIL", "SRP"};
    
    kprintf("\nMutex '%s' (resource %d):\n",
            mutex->name ? mutex->name : "unnamed",
            mutex->resource_id);
    kprintf("  Type: %s\n", type_names[mutex->type]);
    kprintf("  Protocol: %s\n", proto_names[mutex->protocol]);
    kprintf("  Locks: %llu\n", mutex->lock_count);
    kprintf("  Contentions: %llu\n", mutex->contention_count);
    
    if (mutex->type == MUTEX_ADAPTIVE) {
        kprintf("  Spin successes: %llu\n", mutex->spin_success);
        kprintf("  Spin failures: %llu\n", mutex->spin_fail);
        if (mutex->spin_success + mutex->spin_fail > 0) {
            double hit_rate = (double)mutex->spin_success /
                             (mutex->spin_success + mutex->spin_fail) * 100;
            kprintf("  Spin hit rate: %.1f%%\n", hit_rate);
        }
    }
    
    if (mutex->lock_count > 0) {
        double contention_rate = (double)mutex->contention_count /
                                mutex->lock_count * 100;
        kprintf("  Contention rate: %.1f%%\n", contention_rate);
    }
}
