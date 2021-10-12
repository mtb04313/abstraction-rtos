                                                                                                 /***********************************************************************************************//**
 * \file cyabs_rtos_rtthread.c
 *
 * \brief
 * Implementation for RT-Thread abstraction
 *
 ***************************************************************************************************
 * \copyright
 * Copyright 2018-2021 Cypress Semiconductor Corporation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************************************/

#include <cy_result.h>
#include <cy_utils.h>
#include <cyabs_rtos.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/*-- Local Definitions -------------------------------------------------*/

#define USE_CY_MEMTRACK                                   0    // 1:enable; 0:disable

#if USE_CY_MEMTRACK
#include "cy_memtrack.h"
#endif

#define IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE   1    // 1:enable; 0:disable
#define IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE   0    // 1:enable; 0:disable

#define TIME_SLICE_IF_THERE_ARE_SAME_PRIORITY_THREAD      20
#define USE_CY_DEBUG                                      0    // 1:enable; 0:disable

#define RT_ReturnAssert(exp, retvalue) \
    RT_ASSERT((exp)); \
    if (!(exp)) \
        return (retvalue);

#define RT_VoidAssert(exp) \
    RT_ASSERT((exp)); \
    if (!(exp)) \
        return ;

#define MAX_32_BIT (0xFFFFFFFFU)
#define ALL_EVENT_FLAGS (0xFFFFFFFFU)
#define MILLISECONDS_PER_SECOND (1000)

#define INVALID_THREAD_HANDLE       ((cy_thread_t)0xDEADBEEF)


/*-- Local Data -------------------------------------------------*/

static const uint32_t TASK_IDENT      = 0xABCDEF01;

#if (IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE)
static const uint32_t MUTEX_IDENT     = 0xBBCDEF01;
static const uint32_t MUTEX2_IDENT    = 0xBBCDEF02;

#elif (IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE)
static const uint32_t MUTEX3_IDENT    = 0xBBCDEF03;
#endif

static const uint32_t QUEUE_IDENT     = 0xCBCDEF01;
static const uint32_t SEMAPHORE_IDENT = 0xDBCDEF01;
static const uint32_t EVENT_IDENT     = 0xEBCDEF01;
static const uint32_t TIMER_IDENT     = 0xFBCDEF01;

static cy_rtos_error_t s_last_error = RT_EOK;

#if (USE_CY_DEBUG)
#include "cy_debug.h"
static const char *TAG = "rtos_rtt";
#endif


/*-- Local Functions -------------------------------------------------*/

static cy_time_t convert_ms_to_ticks(cy_time_t timeout_ms)
{
    return rt_tick_from_millisecond(timeout_ms);
}

#if 0 // unused
static inline cy_time_t convert_ticks_to_ms(cy_time_t timeout_ticks)
{
    return timeout_ticks * MILLISECONDS_PER_SECOND / RT_TICK_PER_SECOND;
}

static inline cy_rslt_t convert_error(cy_rtos_error_t error)
{
    if (error != RT_EOK) {
        s_last_error = error;
        return CY_RTOS_GENERAL_ERROR;
    }
    return CY_RSLT_SUCCESS;
}
#endif

static void make_name_field( char *name_p,
                             size_t bufsize,
                             char prefix,
                             uint16_t *counter_p)
{
    RT_VoidAssert(name_p != NULL);
    RT_VoidAssert(counter_p != NULL);

    rt_enter_critical();

    snprintf(name_p, bufsize, "%c%d", prefix, *counter_p);
    *counter_p += 1;

    rt_exit_critical();
}


/*-- Public Functions -------------------------------------------------*/

/******************************************************
*                 Last Error
******************************************************/

cy_rtos_error_t cy_rtos_last_error(void)
{
    return s_last_error;
}

/******************************************************
*                 Threads
******************************************************/

typedef struct {
    rt_thread_t thread;
    cy_semaphore_t sem;
    uint32_t magic;
    void *memptr;
} cy_task_wrapper_t;


cy_rslt_t cy_rtos_create_thread(cy_thread_t *thread,
                                cy_thread_entry_fn_t entry_function,
                                const char *name,
                                void *stack,
                                uint32_t stack_size,
                                cy_thread_priority_t priority,
                                cy_thread_arg_t arg)
{
    size_t malloc_size;
    void *buffer;
    cy_task_wrapper_t *wrapper_ptr;

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(name != NULL, CY_RTOS_BAD_PARAM);

    stack_size &= ~CY_RTOS_ALIGNMENT_MASK;      // make stack pointer 8-byte aligned
    RT_ReturnAssert(stack_size >= CY_RTOS_MIN_STACK_SIZE, CY_RTOS_BAD_PARAM);

    RT_ReturnAssert((stack == NULL) ||
                    ((stack != NULL)
                     && (0 == (((uint32_t) stack) & CY_RTOS_ALIGNMENT_MASK))),
                    CY_RTOS_ALIGNMENT_ERROR);

    malloc_size = sizeof(cy_task_wrapper_t);
    if (stack == NULL) {
        malloc_size += stack_size;
    }

#if USE_CY_MEMTRACK
    buffer = CY_MEMTRACK_MALLOC(malloc_size);
#else
    buffer = malloc(malloc_size);
#endif

    RT_ReturnAssert(buffer != NULL, CY_RTOS_NO_MEMORY);
    memset(buffer, 0, malloc_size);

    if (stack == NULL) {
        stack = buffer;
        // Have stack be in front of wrapper since stack size is 8-byte aligned.
        wrapper_ptr = (cy_task_wrapper_t *) (buffer + stack_size);
        wrapper_ptr->memptr = stack;
    }
    else {
        wrapper_ptr = buffer;
        wrapper_ptr->memptr = NULL;
    }
    wrapper_ptr->magic = TASK_IDENT;

    do {
        cy_rslt_t status;
        char temp_name[RT_NAME_MAX];

        // truncate name if needed
        snprintf(temp_name, sizeof(temp_name), "%s", name);

#if (USE_CY_DEBUG)
        CY_LOGD(TAG, "name = %s, temp_name = %s, RT_NAME_MAX = %d", name, temp_name, RT_NAME_MAX);
#endif

        status = cy_rtos_init_semaphore(&wrapper_ptr->sem, 1, 0);
        if (status != CY_RSLT_SUCCESS) {
            break;
        }

        wrapper_ptr->thread = rt_thread_create(temp_name, //name,
                                               entry_function,
                                               arg,
                                               stack_size,
                                               priority,
                                               TIME_SLICE_IF_THERE_ARE_SAME_PRIORITY_THREAD);

        if (wrapper_ptr->thread == RT_NULL) {
            break;
        }

#if (USE_CY_DEBUG)
        CY_LOGD(TAG, "%s [%d]: name = %s, stack_size = %d, priority = %d, rt_thread_t = %p, wrapper_ptr = %p",
                 __FUNCTION__, __LINE__, temp_name, stack_size, priority, wrapper_ptr->thread, wrapper_ptr);
#endif

        wrapper_ptr->thread->user_data = (rt_ubase_t) wrapper_ptr;

        *thread = (cy_thread_t) wrapper_ptr;

        rt_thread_startup(wrapper_ptr->thread);

        return CY_RSLT_SUCCESS;
    } while (0);


    if (wrapper_ptr->sem != NULL) {
        cy_rtos_deinit_semaphore(&wrapper_ptr->sem);
    }

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(buffer);
#else
    free(buffer);
#endif

    s_last_error = RT_ENOMEM;
    return CY_RTOS_NO_MEMORY;
}

cy_rslt_t cy_rtos_exit_thread(void)
{
    cy_task_wrapper_t *wrapper_ptr;
    cy_thread_t handle;
    cy_rslt_t result = cy_rtos_get_thread_handle(&handle);

    if (result != CY_RSLT_SUCCESS) {
        return result;
    }

    /*
     * Instead of deleting here, we use a
     * semaphore to indicate that we can delete and then join waits on
     * the semaphore.
     */

    wrapper_ptr = ((cy_task_wrapper_t *) handle);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_GENERAL_ERROR);
    RT_ReturnAssert(wrapper_ptr->magic == TASK_IDENT, CY_RTOS_GENERAL_ERROR);

#if USE_CY_DEBUG
    DEBUG_PRINT(("%s [%d] set_semaphore\n", __FUNCTION__, __LINE__));
#endif

    /* This signals to the thread deleting the current thread that it
     * it is safe to delete the current thread.
     */
    cy_rtos_set_semaphore(&wrapper_ptr->sem, false);

    /* RT-thread rt_thread_exit() will be automatically invoked when
     * the task function returns.  So we don't need to do anything
     * here, just let the function returns.
     */

    /* This function is not expected to return and calling cy_rtos_join_thread
     * will call rt_thread_delete on this thread and clean up.
     */
    //rt_thread_suspend(wrapper_ptr->thread);
    //while (true);

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_terminate_thread(cy_thread_t * thread)
{
    cy_task_wrapper_t *wrapper_ptr;

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = ((cy_task_wrapper_t *) * thread);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TASK_IDENT, CY_RTOS_BAD_PARAM);

    if (rt_object_get_type((rt_object_t)wrapper_ptr->thread) == RT_Object_Class_Thread) {
#if USE_CY_DEBUG
        DEBUG_PRINT(("%s [%d] call rt_thread_delete\n", __FUNCTION__, __LINE__));
#endif
        rt_thread_delete(wrapper_ptr->thread);

    } else {
#if USE_CY_DEBUG
        DEBUG_PRINT(("%s [%d] rt_thread_delete already called\n", __FUNCTION__, __LINE__));
#endif
    }

    rt_enter_critical();

    wrapper_ptr->thread = NULL;
    wrapper_ptr->magic = 0;
    cy_rtos_deinit_semaphore(&wrapper_ptr->sem);

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr->memptr);
#else
    free(wrapper_ptr->memptr);
#endif

    rt_exit_critical();

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_is_thread_running(cy_thread_t *thread,
                                    bool *running)
{
    cy_thread_state_t state;
    cy_rslt_t status;

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(running != NULL, CY_RTOS_BAD_PARAM);

    status = cy_rtos_get_thread_state(thread, &state);

    if (status == CY_RSLT_SUCCESS) {
        *running = (state == CY_THREAD_STATE_RUNNING);
    }

    return status;
}

cy_rslt_t cy_rtos_get_thread_state(cy_thread_t *thread,
                                   cy_thread_state_t *state)
{
    cy_task_wrapper_t *wrapper_ptr;
    rt_thread_t rt;
    register rt_base_t stat;

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(state != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_task_wrapper_t *) (*thread);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TASK_IDENT, CY_RTOS_BAD_PARAM);

    rt = wrapper_ptr->thread;
    RT_ReturnAssert(rt != NULL, CY_RTOS_GENERAL_ERROR);
    RT_ReturnAssert(rt_object_get_type((rt_object_t) rt) == RT_Object_Class_Thread,
                    CY_RTOS_GENERAL_ERROR);

    stat = rt->stat & RT_THREAD_STAT_MASK;

    switch (stat) {
    case RT_THREAD_INIT:
        *state = CY_THREAD_STATE_INACTIVE;
        break;

    case RT_THREAD_READY:
        *state = CY_THREAD_STATE_READY;
        break;

    case RT_THREAD_RUNNING:
        *state = CY_THREAD_STATE_RUNNING;
        break;

    case RT_THREAD_SUSPEND:    /* same as RT_THREAD_BLOCK */
        *state = CY_THREAD_STATE_BLOCKED;
        break;

    case RT_THREAD_CLOSE:
        *state = CY_THREAD_STATE_TERMINATED;
        break;

    default:
        *state = CY_THREAD_STATE_UNKNOWN;
        break;
    }

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_join_thread(cy_thread_t *thread)
{
    cy_task_wrapper_t *wrapper_ptr;
    cy_rslt_t status = CY_RSLT_SUCCESS;

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_task_wrapper_t *) (*thread);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);

    // This makes sure that the thread to be deleted has completed.  See cy_rtos_exit_thread()
    // for description of why this is done.
    if (wrapper_ptr->magic == TASK_IDENT) {
#if USE_CY_DEBUG
        DEBUG_PRINT(("%s [%d] get_semaphore\n", __FUNCTION__, __LINE__));
#endif

        status = cy_rtos_get_semaphore(&wrapper_ptr->sem, CY_RTOS_NEVER_TIMEOUT, false);
        if (status == CY_RSLT_SUCCESS) {
#if USE_CY_DEBUG
            DEBUG_PRINT(("%s [%d] got_semaphore, call cy_rtos_terminate_thread\n", __FUNCTION__, __LINE__));
#endif

            status = cy_rtos_terminate_thread(thread);
            *thread = NULL;
        }

    } else {
#if USE_CY_DEBUG
        DEBUG_PRINT(("%s [%d] cy_rtos_terminate_thread already called\n", __FUNCTION__, __LINE__));
#endif
    }

    return status;
}

cy_rslt_t cy_rtos_get_thread_handle(cy_thread_t *thread)
{
    rt_thread_t rt;
    cy_task_wrapper_t *wrapper_ptr;

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);

    rt = rt_thread_self();
    RT_ReturnAssert(rt != NULL, CY_RTOS_GENERAL_ERROR);
    RT_ReturnAssert(rt_object_get_type((rt_object_t) rt) == RT_Object_Class_Thread,
                    CY_RTOS_GENERAL_ERROR);

    wrapper_ptr = (cy_task_wrapper_t *) (rt->user_data);
    *thread = (cy_thread_t) wrapper_ptr;

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_wait_thread_notification(cy_time_t num_ms)
{
    rt_err_t result;

    // make num_ms < (RT_TICK_MAX / 2) to keep rt-thread happy
    if (num_ms >= (RT_TICK_MAX / 2)) {
        num_ms = RT_TICK_MAX / 2 - 1;
    }

    result = rt_thread_mdelay(num_ms);
    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT;
}

cy_rslt_t cy_rtos_set_thread_notification(cy_thread_t* thread, bool in_isr)
{
    rt_err_t result;
    cy_task_wrapper_t *wrapper_ptr;
    (void)in_isr;   // unused

    RT_ReturnAssert(thread != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_task_wrapper_t *) (*thread);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TASK_IDENT, CY_RTOS_BAD_PARAM);

    result = rt_thread_resume(wrapper_ptr->thread);
    s_last_error = result;

    return CY_RSLT_SUCCESS;
}

/******************************************************
*                 Mutexes
*
* Native RT-Thread Mutex can support recursive mode.
* However native RT-Thread Mutex cannot be used in ISR.
*
* Native RT-Thread Semaphore cannot support recursive mode.
* However native RT-Thread Semaphore can be used in ISR.
*
* The RT-Thread abstraction-rtos implementation is done in 3 ways:
* 1. use native RT-Thread Semaphore only
*    (i.e. IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE = 0
*     and  IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE = 0)
*    Disadvantage: cannot be used if recursive is set
*
* 2. use native RT-Thread Semaphore enhanced to support recursive mode
*    (i.e. IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE = 1)
*    Advantage: can be used in ISR, and can be used if recursive is set
*
* 3. use native RT-Thread Mutex if recursive flag is set, otherwise use Semaphore
*    (i.e. IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE = 1)
*    Disadvantage: cannot be used in ISR if recursive is set
*
******************************************************/

#if (IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE)
#define MUTEX_NAME_PREFIX_CHAR  'm'

typedef struct {
    rt_mutex_t mutex;
    uint32_t magic;
} cy_mutex_wrapper_t;


static cy_rslt_t internal_rtos_init_mutex(cy_mutex_wrapper_t **mutex,
                                          bool recursive)
{
    cy_mutex_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);
    (void) recursive;           // unused parameter

    do {
        static uint16_t counter = 0;
        char name[RT_NAME_MAX];

#if USE_CY_MEMTRACK
        wrapper_ptr = (cy_mutex_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(cy_mutex_wrapper_t));
#else
        wrapper_ptr = (cy_mutex_wrapper_t *) malloc(sizeof(cy_mutex_wrapper_t));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        wrapper_ptr->magic = MUTEX_IDENT;

        make_name_field(name,
                        sizeof(name),
                        MUTEX_NAME_PREFIX_CHAR,
                        &counter);

        wrapper_ptr->mutex = rt_mutex_create(name,
                                             RT_IPC_FLAG_FIFO);
        if (wrapper_ptr->mutex == NULL) {
            break;
        }

        *mutex = wrapper_ptr;
        return CY_RSLT_SUCCESS;

    } while (0);

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;
}

static cy_rslt_t internal_rtos_get_mutex(cy_mutex_wrapper_t ** mutex,
                                         cy_time_t timeout_ms)
{
    cy_mutex_wrapper_t *wrapper_ptr = NULL;
    cy_time_t ticks;
    rt_err_t result;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX_IDENT, CY_RTOS_BAD_PARAM);

    ticks = convert_ms_to_ticks(timeout_ms);
    result = rt_mutex_take(wrapper_ptr->mutex, ticks);
    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT;
}

static cy_rslt_t internal_rtos_set_mutex(cy_mutex_wrapper_t **mutex)
{
    cy_mutex_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX_IDENT, CY_RTOS_BAD_PARAM);

    result = rt_mutex_release(wrapper_ptr->mutex);
    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT;
}

static cy_rslt_t internal_rtos_deinit_mutex(cy_mutex_wrapper_t **mutex)
{
    cy_mutex_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX_IDENT, CY_RTOS_BAD_PARAM);

    rt_enter_critical();

    result = rt_mutex_delete(wrapper_ptr->mutex);
    s_last_error = result;

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    rt_exit_critical();

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT;
}

typedef struct {
    uint32_t magic;
    cy_mutex_wrapper_t *mutex_impl;
    void *sem_impl;
} cy_mutex2_wrapper_t;

#endif


#if (IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE)

typedef struct {
    uint32_t magic;
    bool recursive;
    cy_thread_t locked_by_thread;
    void *sem_impl;
} cy_mutex3_wrapper_t;

#endif


cy_rslt_t cy_rtos_init_mutex2(cy_mutex_t * mutex,
                              bool recursive)
{
#if (IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE)
    cy_mutex2_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    do {
        cy_rslt_t status;

#if USE_CY_MEMTRACK
        wrapper_ptr = (cy_mutex2_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(cy_mutex2_wrapper_t));
#else
        wrapper_ptr = (cy_mutex2_wrapper_t *) malloc(sizeof(cy_mutex2_wrapper_t));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        memset(wrapper_ptr, 0, sizeof(cy_mutex2_wrapper_t));
        wrapper_ptr->magic = MUTEX2_IDENT;

        if (recursive) {
            status = internal_rtos_init_mutex(&(wrapper_ptr->mutex_impl), recursive);
        }
        else {
            status = cy_rtos_init_semaphore(&(wrapper_ptr->sem_impl), 1, 1);
        }

        if ((wrapper_ptr->mutex_impl == NULL) && (wrapper_ptr->sem_impl == NULL)) {
            /* at least 1 impl must be valid */
            break;
        }

        *mutex = (cy_mutex_t) wrapper_ptr;
        return status;

    } while (0);

    /* clean up on failure */
#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;

#elif (IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE)
    cy_mutex3_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    do {
        cy_rslt_t status;

#if USE_CY_MEMTRACK
        wrapper_ptr = (cy_mutex3_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(*wrapper_ptr));
#else
        wrapper_ptr = (cy_mutex3_wrapper_t *) malloc(sizeof(*wrapper_ptr));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        memset(wrapper_ptr, 0, sizeof(*wrapper_ptr));
        wrapper_ptr->magic = MUTEX3_IDENT;
        wrapper_ptr->recursive = recursive;
        wrapper_ptr->locked_by_thread = INVALID_THREAD_HANDLE;

        status = cy_rtos_init_semaphore(&(wrapper_ptr->sem_impl), 1, 1);

        if (wrapper_ptr->sem_impl == NULL) {
            break;
        }

        *mutex = (cy_mutex_t) wrapper_ptr;
        return status;

    } while (0);

    /* clean up on failure */
#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;

#else
    /*
       if (recursive) {
       CY_ASSERT(0);   // recursive semaphore is not supported
       }
     */
    return cy_rtos_init_semaphore(mutex, 1, 1);

#endif
}

cy_rslt_t cy_rtos_get_mutex(cy_mutex_t * mutex,
                            cy_time_t timeout_ms)
{
#if (IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE)
    cy_mutex2_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex2_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX2_IDENT, CY_RTOS_BAD_PARAM);

    if (wrapper_ptr->mutex_impl != NULL) {
        return internal_rtos_get_mutex(&(wrapper_ptr->mutex_impl), timeout_ms);
    }
    else if (wrapper_ptr->sem_impl != NULL) {
        return cy_rtos_get_semaphore(&(wrapper_ptr->sem_impl), timeout_ms, false);
    }

    return CY_RTOS_BAD_PARAM;

#elif (IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE)
    cy_rslt_t result;
    cy_mutex3_wrapper_t *wrapper_ptr = NULL;
    cy_thread_t current_thread = INVALID_THREAD_HANDLE;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex3_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX3_IDENT, CY_RTOS_BAD_PARAM);

    result = cy_rtos_get_thread_handle(&current_thread);

    RT_ReturnAssert(result == CY_RSLT_SUCCESS, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(current_thread != INVALID_THREAD_HANDLE, CY_RTOS_BAD_PARAM);

    result = CY_RTOS_BAD_PARAM;

    if ((!wrapper_ptr->recursive) ||
        (wrapper_ptr->locked_by_thread != current_thread)) {

        if (wrapper_ptr->sem_impl != NULL) {
            result = cy_rtos_get_semaphore(&(wrapper_ptr->sem_impl), timeout_ms, false);
            if (result == CY_RSLT_SUCCESS) {
                rt_enter_critical();

                wrapper_ptr->locked_by_thread = current_thread;

                rt_exit_critical();
            }
        }
    }
    else {
        result = CY_RSLT_SUCCESS;
        // the same thread is trying to lock the resource a second time,
        // which is okay, let it pass

#if (USE_CY_DEBUG)
        DEBUG_PRINT(("%s [%d] already locked!\n", __FUNCTION__, __LINE__));
#endif
    }

    return result;

#else
    return cy_rtos_get_semaphore(mutex, timeout_ms, false);
#endif
}

cy_rslt_t cy_rtos_set_mutex(cy_mutex_t * mutex)
{
#if (IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE)
    cy_mutex2_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex2_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX2_IDENT, CY_RTOS_BAD_PARAM);

    if (wrapper_ptr->mutex_impl != NULL) {
        return internal_rtos_set_mutex(&(wrapper_ptr->mutex_impl));
    }
    else if (wrapper_ptr->sem_impl != NULL) {
        return cy_rtos_set_semaphore(&(wrapper_ptr->sem_impl), false);
    }

    return CY_RTOS_BAD_PARAM;

#elif (IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE)
    cy_rslt_t result = CY_RTOS_BAD_PARAM;
    cy_mutex3_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex3_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX3_IDENT, CY_RTOS_BAD_PARAM);

    if ((!wrapper_ptr->recursive) ||
        (wrapper_ptr->locked_by_thread != INVALID_THREAD_HANDLE)) {

        if (wrapper_ptr->sem_impl != NULL) {
            result = cy_rtos_set_semaphore(&(wrapper_ptr->sem_impl), false);
            if (result == CY_RSLT_SUCCESS) {
                rt_enter_critical();

                wrapper_ptr->locked_by_thread = INVALID_THREAD_HANDLE;

                rt_exit_critical();
            }
        }
    }
    else {
        result = CY_RSLT_SUCCESS;

#if (USE_CY_DEBUG)
        DEBUG_PRINT(("%s [%d] already unlocked!\n", __FUNCTION__, __LINE__));
#endif
    }

    return result;

#else
    return cy_rtos_set_semaphore(mutex, false);
#endif
}

cy_rslt_t cy_rtos_deinit_mutex(cy_mutex_t * mutex)
{
#if (IMPLEMENT_CY_MUTEX_USING_RT_MUTEX_AND_SEMAPHORE)
    cy_mutex2_wrapper_t *wrapper_ptr = NULL;
    cy_rslt_t status = CY_RTOS_BAD_PARAM;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex2_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX2_IDENT, CY_RTOS_BAD_PARAM);

    if (wrapper_ptr->mutex_impl != NULL) {
        status = internal_rtos_deinit_mutex(&(wrapper_ptr->mutex_impl));
    }
    else if (wrapper_ptr->sem_impl != NULL) {
        status = cy_rtos_deinit_semaphore(&(wrapper_ptr->sem_impl));
    }

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return status;

#elif (IMPLEMENT_CY_MUTEX_USING_RT_SEMAPHORE_RECURSIVE)
    cy_mutex3_wrapper_t *wrapper_ptr = NULL;
    cy_rslt_t status = CY_RTOS_BAD_PARAM;

    RT_ReturnAssert(mutex != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_mutex3_wrapper_t *) (*mutex);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == MUTEX3_IDENT, CY_RTOS_BAD_PARAM);

    if (wrapper_ptr->sem_impl != NULL) {
        rt_enter_critical();

        status = cy_rtos_deinit_semaphore(&(wrapper_ptr->sem_impl));

        rt_exit_critical();
    }

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return status;

#else
    return cy_rtos_deinit_semaphore(mutex);
#endif
}


/******************************************************
*                 Semaphores
******************************************************/

#define SEMAPHORE_NAME_PREFIX_CHAR  's'

typedef struct {
    rt_sem_t sem;
    uint32_t magic;
    uint32_t maxcount;
} cy_semaphore_wrapper_t;

cy_rslt_t cy_rtos_init_semaphore(cy_semaphore_t * semaphore,
                                 uint32_t maxcount,
                                 uint32_t initcount)
{
    cy_semaphore_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(semaphore != NULL, CY_RTOS_BAD_PARAM);

    /* RT-Thread semaphore only accepts 1 value parameter, which we expect is a 'initcount' */
    /* Also, we expect initcount to be zero or less than maxcount */
    RT_ReturnAssert(maxcount > 0, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert((maxcount >= initcount), CY_RTOS_BAD_PARAM);

    do {
        static uint16_t counter = 0;
        char name[RT_NAME_MAX];

#if USE_CY_MEMTRACK
        wrapper_ptr =
            (cy_semaphore_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(cy_semaphore_wrapper_t));
#else
        wrapper_ptr =
            (cy_semaphore_wrapper_t *) malloc(sizeof(cy_semaphore_wrapper_t));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        wrapper_ptr->magic = SEMAPHORE_IDENT;
        wrapper_ptr->maxcount = maxcount;

        make_name_field(name,
                        sizeof(name),
                        SEMAPHORE_NAME_PREFIX_CHAR,
                        &counter);

        wrapper_ptr->sem = rt_sem_create(name,
                                         initcount,
                                         RT_IPC_FLAG_FIFO);
        if (wrapper_ptr->sem == NULL) {
            break;
        }

        *semaphore = (cy_semaphore_t) wrapper_ptr;
        return CY_RSLT_SUCCESS;

    } while (0);

    /* clean up on failure */
#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;
}

cy_rslt_t cy_rtos_get_semaphore(cy_semaphore_t * semaphore,
                                cy_time_t timeout_ms,
                                bool in_isr)
{
    cy_semaphore_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(semaphore != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_semaphore_wrapper_t *) (*semaphore);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == SEMAPHORE_IDENT, CY_RTOS_BAD_PARAM);

    if (in_isr) {
        result = rt_sem_trytake(wrapper_ptr->sem);
    }
    else {
        cy_time_t ticks = convert_ms_to_ticks(timeout_ms);
        result = rt_sem_take(wrapper_ptr->sem, ticks);
    }

    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT;
}

cy_rslt_t cy_rtos_set_semaphore(cy_semaphore_t * semaphore,
                                bool in_isr) // unused parameter
{
    cy_semaphore_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(semaphore != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_semaphore_wrapper_t *) (*semaphore);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == SEMAPHORE_IDENT, CY_RTOS_BAD_PARAM);

    (void) in_isr;              // Unused parameter in this implementation

    if ((wrapper_ptr->sem)->value < wrapper_ptr->maxcount) {
        result = rt_sem_release(wrapper_ptr->sem);
    }
    else {
        RT_ReturnAssert(((wrapper_ptr->sem)->value == wrapper_ptr->maxcount),
                        CY_RTOS_GENERAL_ERROR);
        result = -RT_ERROR; //RT_EOK;
    }

    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR; //CY_RTOS_TIMEOUT;
}

cy_rslt_t cy_rtos_get_count_semaphore(cy_semaphore_t * semaphore,
                                      size_t * count)
{
    cy_semaphore_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(semaphore != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(count != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_semaphore_wrapper_t *) (*semaphore);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == SEMAPHORE_IDENT, CY_RTOS_BAD_PARAM);

    *count = (size_t) ((wrapper_ptr->sem)->value);

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_deinit_semaphore(cy_semaphore_t * semaphore)
{
    cy_semaphore_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(semaphore != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_semaphore_wrapper_t *) (*semaphore);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == SEMAPHORE_IDENT, CY_RTOS_BAD_PARAM);

    rt_enter_critical();

    result = rt_sem_delete(wrapper_ptr->sem);
    s_last_error = result;

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    rt_exit_critical();

    RT_ReturnAssert((result == RT_EOK), CY_RTOS_GENERAL_ERROR);

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}


/******************************************************
*                 Events
******************************************************/

#define EVENT_NAME_PREFIX_CHAR  'e'
#define EVENT_USABLE_BITS       0x00FFFFFF  // to be consistent with FreeRTOS implementation

typedef struct {
    rt_event_t event;
    uint32_t magic;
} cy_event_wrapper_t;


cy_rslt_t cy_rtos_init_event(cy_event_t * event)
{
    cy_event_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(event != NULL, CY_RTOS_BAD_PARAM);

    do {
        static uint16_t counter = 0;
        char name[RT_NAME_MAX];

#if USE_CY_MEMTRACK
        wrapper_ptr = (cy_event_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(cy_event_wrapper_t));
#else
        wrapper_ptr = (cy_event_wrapper_t *) malloc(sizeof(cy_event_wrapper_t));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        wrapper_ptr->magic = EVENT_IDENT;

        make_name_field(name,
                        sizeof(name),
                        EVENT_NAME_PREFIX_CHAR,
                        &counter);

        wrapper_ptr->event = rt_event_create(name,
                                             RT_IPC_FLAG_FIFO);
        if (wrapper_ptr->event == NULL) {
            break;
        }

        *event = (cy_event_t) wrapper_ptr;
        return CY_RSLT_SUCCESS;

    } while (0);

    /* clean up on failure */
#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;
}

cy_rslt_t cy_rtos_setbits_event(cy_event_t * event,
                                uint32_t bits,
                                bool in_isr)
{
    cy_event_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(event != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert((bits & (~EVENT_USABLE_BITS)) == 0, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_event_wrapper_t *) (*event);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == EVENT_IDENT, CY_RTOS_BAD_PARAM);

    (void) in_isr;              // Unused parameter in this implementation

    result = rt_event_send(wrapper_ptr->event, bits);
    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_clearbits_event(cy_event_t * event,
                                  uint32_t bits,
                                  bool in_isr)
{
    cy_event_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(event != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert((bits & (~EVENT_USABLE_BITS)) == 0, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_event_wrapper_t *) (*event);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == EVENT_IDENT, CY_RTOS_BAD_PARAM);

    (void) in_isr;              // Unused parameter in this implementation

    // trying to clear bits when already 'clean', should produce an error
    if ((wrapper_ptr->event)->set == 0) {
        return CY_RTOS_GENERAL_ERROR;
    }

    rt_enter_critical();

    (wrapper_ptr->event)->set &= ~bits; // clear it here

    rt_exit_critical();

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_getbits_event(cy_event_t * event,
                                uint32_t * bits)
{
    cy_event_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(event != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(bits != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_event_wrapper_t *) (*event);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == EVENT_IDENT, CY_RTOS_BAD_PARAM);

    //rt_enter_critical();

    *bits = (wrapper_ptr->event)->set;

    //rt_exit_critical();

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_waitbits_event(cy_event_t * event,
                                 uint32_t * waitfor,
                                 bool clear,
                                 bool allset,
                                 cy_time_t timeout_ms)
{
    cy_event_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;
    rt_uint8_t option;
    rt_uint32_t set;
    cy_time_t ticks;
    rt_uint32_t recved = 0;
    rt_uint32_t setbits;

    RT_ReturnAssert(event != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(waitfor != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(*waitfor != 0, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert((*waitfor & (~EVENT_USABLE_BITS)) == 0, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_event_wrapper_t *) (*event);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == EVENT_IDENT, CY_RTOS_BAD_PARAM);

    set = *waitfor;
    option = allset ? RT_EVENT_FLAG_AND : RT_EVENT_FLAG_OR;

    /* Not using this flag because it does not give us a chance to
     * save the event before it gets 'cleared'
    if (clear) {
        option |= RT_EVENT_FLAG_CLEAR;
    }
    */

    ticks = convert_ms_to_ticks(timeout_ms);
    result = rt_event_recv(wrapper_ptr->event, set, option, ticks, &recved);

    rt_enter_critical();

    setbits = (wrapper_ptr->event)->set;     // save the triggered event before clearing
    if ((result == RT_EOK) && clear) {
        (wrapper_ptr->event)->set &= (~set); // clear it here
    }

    rt_exit_critical();

    s_last_error = result;

    if ((result == RT_EOK) || (result == -RT_ETIMEOUT)) {
        *waitfor = setbits;
    }

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT;
}

cy_rslt_t cy_rtos_deinit_event(cy_event_t * event)
{
    cy_event_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(event != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_event_wrapper_t *) (*event);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == EVENT_IDENT, CY_RTOS_BAD_PARAM);

    rt_enter_critical();

    result = rt_event_delete(wrapper_ptr->event);
    s_last_error = result;

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    rt_exit_critical();

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}


/******************************************************
*                 Queues
******************************************************/

#define QUEUE_NAME_PREFIX_CHAR  'q'

typedef struct {
    rt_mq_t queue;
    uint32_t magic;
} cy_queue_wrapper_t;


cy_rslt_t cy_rtos_init_queue(cy_queue_t * queue,
                             size_t length,
                             size_t itemsize)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);

    do {
        static uint16_t counter = 0;
        char name[RT_NAME_MAX];

#if USE_CY_MEMTRACK
        wrapper_ptr = (cy_queue_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(cy_queue_wrapper_t));
#else
        wrapper_ptr = (cy_queue_wrapper_t *) malloc(sizeof(cy_queue_wrapper_t));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        wrapper_ptr->magic = QUEUE_IDENT;

        make_name_field(name,
                        sizeof(name),
                        QUEUE_NAME_PREFIX_CHAR,
                        &counter);

        wrapper_ptr->queue = rt_mq_create(name,
                                          itemsize,
                                          length,
                                          RT_IPC_FLAG_FIFO);
        if (wrapper_ptr->queue == NULL) {
            break;
        }

        *queue = (cy_queue_t) wrapper_ptr;
        return CY_RSLT_SUCCESS;

    } while (0);

    /* clean up on failure */
#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;
}

cy_rslt_t cy_rtos_put_queue(cy_queue_t * queue,
                            const void *item_ptr,
                            cy_time_t timeout_ms,
                            bool in_isr)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(item_ptr != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_queue_wrapper_t *) (*queue);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == QUEUE_IDENT, CY_RTOS_BAD_PARAM);

    if (in_isr) {
        result = rt_mq_send(wrapper_ptr->queue,
                            item_ptr, (wrapper_ptr->queue)->msg_size);
    }
    else {
        cy_time_t ticks = convert_ms_to_ticks(timeout_ms);
        result = rt_mq_send_wait(wrapper_ptr->queue,
                                 item_ptr, (wrapper_ptr->queue)->msg_size, ticks);
    }

    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_get_queue(cy_queue_t * queue,
                            void *item_ptr,
                            cy_time_t timeout_ms,
                            bool in_isr)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;
    cy_time_t ticks;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(item_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(!in_isr, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_queue_wrapper_t *) (*queue);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == QUEUE_IDENT, CY_RTOS_BAD_PARAM);

    ticks = convert_ms_to_ticks(timeout_ms);
    result = rt_mq_recv(wrapper_ptr->queue,
                        item_ptr, (wrapper_ptr->queue)->msg_size, ticks);

    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_count_queue(cy_queue_t * queue,
                              size_t * num_waiting)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(num_waiting != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_queue_wrapper_t *) (*queue);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == QUEUE_IDENT, CY_RTOS_BAD_PARAM);

    //rt_enter_critical();

    *num_waiting = (wrapper_ptr->queue)->entry;

    //rt_exit_critical();

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_space_queue(cy_queue_t * queue,
                              size_t * num_spaces)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(num_spaces != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_queue_wrapper_t *) (*queue);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == QUEUE_IDENT, CY_RTOS_BAD_PARAM);

    rt_enter_critical();

    *num_spaces = (wrapper_ptr->queue)->max_msgs - (wrapper_ptr->queue)->entry;

    rt_exit_critical();

    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_reset_queue(cy_queue_t * queue)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_queue_wrapper_t *) (*queue);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == QUEUE_IDENT, CY_RTOS_BAD_PARAM);

    result = rt_mq_control(wrapper_ptr->queue, RT_IPC_CMD_RESET, NULL);

    s_last_error = result;
    RT_ReturnAssert((result == RT_EOK), CY_RTOS_GENERAL_ERROR);

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_deinit_queue(cy_queue_t * queue)
{
    cy_queue_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(queue != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_queue_wrapper_t *) (*queue);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == QUEUE_IDENT, CY_RTOS_BAD_PARAM);

    rt_enter_critical();

    result = rt_mq_delete(wrapper_ptr->queue);
    s_last_error = result;

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    rt_exit_critical();

    RT_ReturnAssert((result == RT_EOK), CY_RTOS_GENERAL_ERROR);

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}


/******************************************************
*                 Timers
******************************************************/

#define TIMER_NAME_PREFIX_CHAR  't'

typedef struct {
    rt_timer_t timer;
    uint32_t magic;
} cy_timer_wrapper_t;

cy_rslt_t cy_rtos_init_timer(cy_timer_t * timer,
                             cy_timer_trigger_type_t type,
                             cy_timer_callback_t fun,
                             cy_timer_callback_arg_t arg)
{
    cy_timer_wrapper_t *wrapper_ptr = NULL;
    rt_uint8_t flag;

    RT_ReturnAssert(timer != NULL, CY_RTOS_BAD_PARAM);

    do {
        static uint16_t counter = 0;
        char name[RT_NAME_MAX];

#if USE_CY_MEMTRACK
        wrapper_ptr = (cy_timer_wrapper_t *) CY_MEMTRACK_MALLOC(sizeof(cy_timer_wrapper_t));
#else
        wrapper_ptr = (cy_timer_wrapper_t *) malloc(sizeof(cy_timer_wrapper_t));
#endif

        RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_NO_MEMORY);

        wrapper_ptr->magic = TIMER_IDENT;

        flag = (type == CY_TIMER_TYPE_PERIODIC)
            ? RT_TIMER_FLAG_PERIODIC : RT_TIMER_FLAG_ONE_SHOT;

        make_name_field(name,
                        sizeof(name),
                        TIMER_NAME_PREFIX_CHAR,
                        &counter);

        wrapper_ptr->timer = rt_timer_create(name,
                                             fun,
                                             arg,
                                             1,
                                             flag);
        if (wrapper_ptr->timer == NULL) {
            break;
        }

        *timer = (cy_timer_t) wrapper_ptr;
        return CY_RSLT_SUCCESS;

    } while (0);

    /* clean up on failure */
#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    return CY_RTOS_NO_MEMORY;
}

cy_rslt_t cy_rtos_start_timer(cy_timer_t * timer,
                              cy_time_t num_ms)
{
    cy_timer_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;
    cy_time_t ticks;

    RT_ReturnAssert(timer != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_timer_wrapper_t *) (*timer);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TIMER_IDENT, CY_RTOS_BAD_PARAM);

    ticks = convert_ms_to_ticks(num_ms);

    result = rt_timer_control(wrapper_ptr->timer, RT_TIMER_CTRL_SET_TIME, &ticks);

    if (result == RT_EOK) {
        result = rt_timer_start(wrapper_ptr->timer);
    }
    s_last_error = result;

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_stop_timer(cy_timer_t * timer)
{
    cy_timer_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(timer != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_timer_wrapper_t *) (*timer);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TIMER_IDENT, CY_RTOS_BAD_PARAM);

    result = rt_timer_stop(wrapper_ptr->timer);
    s_last_error = result;

    if ((result == -RT_ERROR) &&
        !(wrapper_ptr->timer->parent.flag & RT_TIMER_FLAG_ACTIVATED)) {
        // timer already stopped
        return CY_RSLT_SUCCESS;
    }

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_is_running_timer(cy_timer_t * timer,
                                   bool * state)
{
    cy_timer_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;
    rt_tick_t state_flag;

    RT_ReturnAssert(timer != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(state != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_timer_wrapper_t *) (*timer);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TIMER_IDENT, CY_RTOS_BAD_PARAM);

    result = rt_timer_control(wrapper_ptr->timer,
                              RT_TIMER_CTRL_GET_STATE, &state_flag);
    s_last_error = result;

    if (result == RT_EOK) {
        *state = (state_flag == RT_TIMER_FLAG_ACTIVATED)
            ? true : false;
    }

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}

cy_rslt_t cy_rtos_deinit_timer(cy_timer_t * timer)
{
    cy_timer_wrapper_t *wrapper_ptr = NULL;
    rt_err_t result;

    RT_ReturnAssert(timer != NULL, CY_RTOS_BAD_PARAM);

    wrapper_ptr = (cy_timer_wrapper_t *) (*timer);
    RT_ReturnAssert(wrapper_ptr != NULL, CY_RTOS_BAD_PARAM);
    RT_ReturnAssert(wrapper_ptr->magic == TIMER_IDENT, CY_RTOS_BAD_PARAM);

    rt_enter_critical();

    result = rt_timer_delete(wrapper_ptr->timer);
    s_last_error = result;

#if USE_CY_MEMTRACK
    CY_MEMTRACK_FREE(wrapper_ptr);
#else
    free(wrapper_ptr);
#endif

    rt_exit_critical();

    return (result == RT_EOK)
        ? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR;
}


/******************************************************
*                 Time
******************************************************/

cy_rslt_t cy_rtos_get_time(cy_time_t * tval)
{
    RT_ReturnAssert(tval != NULL, CY_RTOS_BAD_PARAM);

    *tval = (cy_time_t) rt_tick_get_millisecond();
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_rtos_delay_milliseconds(cy_time_t num_ms)
{
    return rt_thread_mdelay(num_ms);
}
