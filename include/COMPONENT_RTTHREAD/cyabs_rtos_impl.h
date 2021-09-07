/***********************************************************************************************//**
 * \file cyabs_rtos_impl.h
 *
 * \brief
 * Internal definitions for RTOS abstraction layer
 *
 ***************************************************************************************************
 * \copyright
 * Copyright 2019-2021 Cypress Semiconductor Corporation
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

#ifndef INCLUDED_CYABS_RTOS_IMPL_H_
#define INCLUDED_CYABS_RTOS_IMPL_H_

#include <rtthread.h>

#ifdef __cplusplus
extern "C"
{
#endif

/******************************************************
*                 Constants
******************************************************/
#define CY_RTOS_MIN_STACK_SIZE      300                     /**< Minimum stack size */
#define CY_RTOS_ALIGNMENT           0x00000008UL            /** Minimum alignment for RTOS objects */
#define CY_RTOS_ALIGNMENT_MASK      0x00000007UL            /**< Checks for 8-bit alignment */


/******************************************************
*                 Type Definitions
******************************************************/

/** RTOS thread priority */
typedef enum
{
    /* RT-Thread: smaller number => higher priority */
    CY_RTOS_PRIORITY_MIN         = (RT_THREAD_PRIORITY_MAX - 1),     /**< Minumum allowable Thread priority */
    CY_RTOS_PRIORITY_LOW         = (RT_THREAD_PRIORITY_MAX / 7) * 6, /**< A low priority Thread */
    CY_RTOS_PRIORITY_BELOWNORMAL = (RT_THREAD_PRIORITY_MAX / 7) * 5, /**< A slightly below normal Thread priority */
    CY_RTOS_PRIORITY_NORMAL      = (RT_THREAD_PRIORITY_MAX / 7) * 4, /**< The normal Thread priority */
    CY_RTOS_PRIORITY_ABOVENORMAL = (RT_THREAD_PRIORITY_MAX / 7) * 3, /**< A slightly elevated Thread priority */
    CY_RTOS_PRIORITY_HIGH        = (RT_THREAD_PRIORITY_MAX / 7) * 2, /**< A high priority Thread */
    CY_RTOS_PRIORITY_REALTIME    = (RT_THREAD_PRIORITY_MAX / 7) * 1, /**< Realtime Thread priority */
    CY_RTOS_PRIORITY_MAX         = 0,                                /**< Maximum allowable Thread priority */
} cy_thread_priority_t ;


typedef void* cy_thread_t;             /**< Alias for the RTOS specific definition of a thread handle */
typedef void* cy_thread_arg_t;         /**< Alias for the RTOS specific argument passed to the entry function of a thread */
typedef void* cy_mutex_t;              /**< Alias for the RTOS specific definition of a mutex */
typedef void* cy_semaphore_t;          /**< Alias for the RTOS specific definition of a semaphore */
typedef void* cy_event_t;              /**< Alias for the RTOS specific definition of an event */
typedef void* cy_queue_t;              /**< Alias for the RTOS specific definition of a message queue */
typedef void* cy_timer_t;              /**< Alias for the RTOS specific definition of a timer */
typedef void* cy_timer_callback_arg_t; /**< Alias for the RTOS specific argument passed to the timer callback function */
typedef uint32_t cy_time_t;            /**< Alias for the RTOS specific time unit (in milliseconds) */
typedef rt_err_t cy_rtos_error_t;      /**< Alias for the RTOS specific definition of a error status */


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ifndef INCLUDED_CYABS_RTOS_IMPL_H_ */
