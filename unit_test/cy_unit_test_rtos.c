/*******************************************************************************
* File Name: cy_unit_test_rtos.c
*
* Description: This file implements abstraction-rtos tests
*
* Related Document: See README.md
*
*
*********************************************************************************
 Copyright 2020-2021, Cypress Semiconductor Corporation (an Infineon company) or
 an affiliate of Cypress Semiconductor Corporation.  All rights reserved.

 This software, including source code, documentation and related
 materials ("Software") is owned by Cypress Semiconductor Corporation
 or one of its affiliates ("Cypress") and is protected by and subject to
 worldwide patent protection (United States and foreign),
 United States copyright laws and international treaty provisions.
 Therefore, you may use this Software only as provided in the license
 agreement accompanying the software package from which you
 obtained this Software ("EULA").
 If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 non-transferable license to copy, modify, and compile the Software
 source code solely for use in connection with Cypress's
 integrated circuit products.  Any reproduction, modification, translation,
 compilation, or representation of this Software except as specified
 above is prohibited without the express written permission of Cypress.

 Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 reserves the right to make changes to the Software without notice. Cypress
 does not assume any liability arising out of the application or use of the
 Software or any product or circuit described in the Software. Cypress does
 not authorize its products for use in any products where a malfunction or
 failure of the Cypress product may reasonably be expected to result in
 significant property damage, injury or death ("High Risk Product"). By
 including Cypress's product in a High Risk Product, the manufacturer
 of such system or application assumes all risk of such use and in doing
 so agrees to indemnify Cypress against all liability.
*******************************************************************************/

#include "feature_config.h"

#if (FEATURE_UNIT_TEST_RTOS == ENABLE_FEATURE)
#include "cy_unit_test_rtos.h"
#include "cy_unit_test_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cy_memtrack.h"
#include "cy_debug.h"
#include "cyabs_rtos.h"


/*-- Local Definitions -------------------------------------------------*/

#define DO_THREAD_TESTS     1   // 1:enable; 0:disable
#define DO_MUTEX_TESTS      1   // 1:enable; 0:disable
#define DO_SEMAPHORE_TESTS  1   // 1:enable; 0:disable
#define DO_EVENT_TESTS      1   // 1:enable; 0:disable
#define DO_QUEUE_TESTS      1   // 1:enable; 0:disable
#define DO_TIMER_TESTS      1   // 1:enable; 0:disable


#define TEST_TASK_STACK_SIZE  (2 * 1024)
#define TEST_TASK_PRIORITY    CY_RTOS_PRIORITY_LOW
#define TEST_TASK_NAME        "Test task"

#define TEST_ARG_CALL_EXIT_THREAD_AND_RETURN    1
#define TEST_ARG_CALL_EXIT_THREAD_AND_LOOP      2
#define TEST_ARG_SKIP_EXIT_THREAD_AND_LOOP      3

#define TEST_ARG_CALL_TERMINATE                 1
#define TEST_ARG_SKIP_TERMINATE                 2

#define WAIT_FOR_THREAD_CREATE_MSEC  1000
#define WAIT_FOR_THREAD_EXIT_MSEC    1000

#define WAIT_FOR_MUTEX_MSEC          1000
#define WAIT_FOR_SEMAPHORE_MSEC      1000
#define WAIT_FOR_EVENT_MSEC          1000
#define WAIT_FOR_QUEUE_MSEC          1000
#define WAIT_FOR_TIMER_MSEC          1000

#define BIT31    0x80000000
#define BIT30    0x40000000
#define BIT29    0x20000000
#define BIT28    0x10000000
#define BIT27    0x08000000
#define BIT26    0x04000000
#define BIT25    0x02000000
#define BIT24    0x01000000

#define BIT23    0x00800000
#define BIT22    0x00400000
#define BIT21    0x00200000
#define BIT20    0x00100000
#define BIT19    0x00080000
#define BIT18    0x00040000
#define BIT17    0x00020000
#define BIT16    0x00010000

#define BIT15    0x00008000
#define BIT14    0x00004000
#define BIT13    0x00002000
#define BIT12    0x00001000
#define BIT11    0x00000800
#define BIT10    0x00000400
#define BIT9     0x00000200
#define BIT8     0x00000100

#define BIT7     0x00000080
#define BIT6     0x00000040
#define BIT5     0x00000020
#define BIT4     0x00000010
#define BIT3     0x00000008
#define BIT2     0x00000004
#define BIT1     0x00000002
#define BIT0     0x00000001


/*-- Local Functions -------------------------------------------------*/

static void print_separator(void)
{
    DEBUG_PRINT(("----------------------------------------------------\n"));
}

static const char *test_mem_leak(size_t before, size_t after)
{
    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));
    ASSERT_TEST(before == after);

    return NULL;
}


#if DO_THREAD_TESTS
static void test_task(cy_thread_arg_t arg)
{
    cy_rslt_t result;
    cy_thread_t my_handle = NULL;
    bool running = false;
    cy_thread_state_t state = CY_THREAD_STATE_UNKNOWN;

    DEBUG_ASSERT(arg != NULL);
    DEBUG_PRINT(("%s [%d] arg = %d\n", __FUNCTION__, __LINE__, (int)arg));

    result = cy_rtos_get_thread_handle(&my_handle);
    DEBUG_PRINT(("my_handle = %p\n", my_handle));
    DEBUG_ASSERT(result == CY_RSLT_SUCCESS);
    DEBUG_ASSERT(my_handle != NULL);

    // a thread who is checking itself must be running
    result = cy_rtos_is_thread_running(&my_handle, &running);
    DEBUG_ASSERT(result == CY_RSLT_SUCCESS);
    DEBUG_ASSERT(running == true);

    result = cy_rtos_get_thread_state(&my_handle, &state);
    DEBUG_ASSERT(result == CY_RSLT_SUCCESS);
    DEBUG_ASSERT(state == CY_THREAD_STATE_RUNNING);

    // wait for notification
    result = cy_rtos_wait_thread_notification(CY_RTOS_NEVER_TIMEOUT);
    DEBUG_ASSERT(result == CY_RSLT_SUCCESS);

    if ((int)arg == TEST_ARG_CALL_EXIT_THREAD_AND_RETURN) {
        DEBUG_PRINT(("%s [%d] received notification, call exit_thread() and return\n", __FUNCTION__, __LINE__));

        result = cy_rtos_exit_thread();
        DEBUG_ASSERT(result == CY_RSLT_SUCCESS);

    } else if ((int)arg == TEST_ARG_CALL_EXIT_THREAD_AND_LOOP) {
        DEBUG_PRINT(("%s [%d] received notification, call exit_thread() and enter while loop\n", __FUNCTION__, __LINE__));

        result = cy_rtos_exit_thread();
        DEBUG_ASSERT(result == CY_RSLT_SUCCESS);
        while(true);

    } else if ((int)arg == TEST_ARG_SKIP_EXIT_THREAD_AND_LOOP) {
        DEBUG_PRINT(("%s [%d] received notification, enter while loop\n", __FUNCTION__, __LINE__));
        while(true);

    } else {
        DEBUG_ASSERT(0);
    }
}

static const char *test_delay_msec(uint32_t delay_msec)
{
    cy_rslt_t result;
    result = cy_rtos_delay_milliseconds(delay_msec);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_create_thread(cy_thread_t *task_handle_p,
                                      int arg)
{
    cy_rslt_t result;

    DEBUG_ASSERT(task_handle_p != NULL);
    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    result = cy_rtos_create_thread( task_handle_p,
                                    test_task,
                                    TEST_TASK_NAME,
                                    NULL,
                                    TEST_TASK_STACK_SIZE,
                                    TEST_TASK_PRIORITY,
                                    (cy_thread_arg_t) arg
                                  );
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_is_thread_running(cy_thread_t *task_handle_p,
                                          bool expected_running,
                                          cy_thread_state_t expected_state)
{
    cy_rslt_t result;
    bool running = false;
    cy_thread_state_t state = CY_THREAD_STATE_UNKNOWN;

    DEBUG_ASSERT(task_handle_p != NULL);
    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    result = cy_rtos_is_thread_running(task_handle_p, &running);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(running == expected_running);

    result = cy_rtos_get_thread_state(task_handle_p, &state);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(state == expected_state);

    return NULL;
}

static const char *test_set_thread_notification(cy_thread_t *task_handle_p)
{
    cy_rslt_t result;

    DEBUG_ASSERT(task_handle_p != NULL);
    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    result = cy_rtos_set_thread_notification(task_handle_p, false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_terminate_thread(cy_thread_t *task_handle_p)
{
    cy_rslt_t result;

    DEBUG_ASSERT(task_handle_p != NULL);
    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    result = cy_rtos_terminate_thread(task_handle_p);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_join_thread(cy_thread_t *task_handle_p)
{
    cy_rslt_t result;

    DEBUG_ASSERT(task_handle_p != NULL);
    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    result = cy_rtos_join_thread(task_handle_p);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *run_thread_tests(int arg1, int arg2)
{
    cy_thread_t task_handle = NULL;
    size_t peak_start, mem_start;
    size_t peak_end, mem_end;

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_start, &mem_start);

    RUN_TEST(test_create_thread(&task_handle, arg1));
    DEBUG_PRINT(("task_handle = %p\n", task_handle));
    RUN_TEST(test_is_thread_running(&task_handle, false, CY_THREAD_STATE_READY));


    RUN_TEST(test_delay_msec(WAIT_FOR_THREAD_CREATE_MSEC));
    RUN_TEST(test_is_thread_running(&task_handle, false, CY_THREAD_STATE_BLOCKED));

    RUN_TEST(test_set_thread_notification(&task_handle));
    RUN_TEST(test_is_thread_running(&task_handle, false, CY_THREAD_STATE_READY));

    RUN_TEST(test_delay_msec(WAIT_FOR_THREAD_EXIT_MSEC));

#ifdef COMPONENT_FREERTOS
    if (arg1 != TEST_ARG_SKIP_EXIT_THREAD_AND_LOOP) {
        RUN_TEST(test_is_thread_running(&task_handle, false, CY_THREAD_STATE_INACTIVE));
    }
#endif

    if (arg2 == TEST_ARG_CALL_TERMINATE) {
        RUN_TEST(test_terminate_thread(&task_handle));

#ifdef COMPONENT_FREERTOS
        RUN_TEST(test_is_thread_running(&task_handle, false, CY_THREAD_STATE_TERMINATED));
#endif
    }

    RUN_TEST(test_join_thread(&task_handle));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_end, &mem_end);
    RUN_TEST(test_mem_leak(mem_start, mem_end));

    return NULL;
}
#endif

#if DO_MUTEX_TESTS
static const char *test_init_mutex(cy_mutex_t* mutex, bool recursive)
{
    cy_rslt_t result;

    if (recursive) {
        result = cy_rtos_init_mutex(mutex);

    } else {
        result = cy_rtos_init_mutex2(mutex, recursive);
    }
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_deinit_mutex(cy_mutex_t* mutex)
{
    cy_rslt_t result;

    result = cy_rtos_deinit_mutex(mutex);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_get_set_mutex(cy_mutex_t* mutex)
{
    cy_rslt_t result;

    result = cy_rtos_get_mutex(mutex, WAIT_FOR_MUTEX_MSEC);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_set_mutex(mutex);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}


static const char *test_get2_set2_mutex(cy_mutex_t* mutex, bool recursive)
{
    cy_rslt_t result;

    result = cy_rtos_get_mutex(mutex, WAIT_FOR_MUTEX_MSEC);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_get_mutex(mutex, WAIT_FOR_MUTEX_MSEC);
    ASSERT_TEST(result == (recursive? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT));

    result = cy_rtos_set_mutex(mutex);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_set_mutex(mutex);
    ASSERT_TEST(result == (recursive? CY_RSLT_SUCCESS : CY_RTOS_GENERAL_ERROR));

    return NULL;
}

static const char *run_mutex_tests(int count)
{
    int i;

    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    for (i = 0; i < count; i++) {
        size_t peak_start, mem_start;
        size_t peak_end, mem_end;

        CY_MEMTRACK_MALLOC_STATS_EX(&peak_start, &mem_start);

        DEBUG_PRINT(("recursive mutex\n"));
        cy_mutex_t mutex;
        bool recursive;

        recursive = true;
        RUN_TEST(test_init_mutex(&mutex, recursive));
        RUN_TEST(test_get_set_mutex(&mutex));
        RUN_TEST(test_get2_set2_mutex(&mutex, recursive));
        RUN_TEST(test_deinit_mutex(&mutex));

        DEBUG_PRINT(("non-recursive mutex\n"));
        recursive = false;
        RUN_TEST(test_init_mutex(&mutex, recursive));
        RUN_TEST(test_get_set_mutex(&mutex));
        RUN_TEST(test_get2_set2_mutex(&mutex, recursive));
        RUN_TEST(test_deinit_mutex(&mutex));

        CY_MEMTRACK_MALLOC_STATS_EX(&peak_end, &mem_end);
        RUN_TEST(test_mem_leak(mem_start, mem_end));
    }

    return NULL;
}

#endif

#if DO_SEMAPHORE_TESTS

static const char *test_init_semaphore( cy_semaphore_t* sem,
                                        uint32_t maxcount,
                                        uint32_t initcount)
{
    cy_rslt_t result;

    DEBUG_PRINT(("%s [%d] maxcount = %lu, initcount = %lu\n",
                __FUNCTION__, __LINE__, maxcount, initcount));
    result = cy_rtos_init_semaphore(sem, maxcount, initcount);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_deinit_semaphore(cy_semaphore_t* sem)
{
    cy_rslt_t result;

    result = cy_rtos_deinit_semaphore(sem);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_get_set_semaphore(cy_semaphore_t* sem,
                                          uint32_t maxcount,
                                          uint32_t initcount)
{
    cy_rslt_t result;
    size_t count;

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(count == initcount);

    result = cy_rtos_get_semaphore(sem, WAIT_FOR_SEMAPHORE_MSEC, false);
    ASSERT_TEST(result == (initcount > 0? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT));

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(count == (initcount > 0? (initcount - 1) : initcount));

    result = cy_rtos_set_semaphore(sem, false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(count == (initcount > 0? initcount : (initcount + 1)));

    return NULL;
}


static const char *test_get2_set2_semaphore(cy_semaphore_t* sem,
                                            uint32_t maxcount,
                                            uint32_t initcount)
{
    cy_rslt_t result;
    size_t count;

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(count == initcount);

    result = cy_rtos_get_semaphore(sem, WAIT_FOR_SEMAPHORE_MSEC, false);
    ASSERT_TEST(result == (initcount > 0? CY_RSLT_SUCCESS : CY_RTOS_TIMEOUT));

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(count == (initcount > 0? (initcount - 1) : initcount));

    result = cy_rtos_get_semaphore(sem, WAIT_FOR_SEMAPHORE_MSEC, false);
    if (initcount > 1) {
        ASSERT_TEST(result == CY_RSLT_SUCCESS);
    } else {
        ASSERT_TEST(result == CY_RTOS_TIMEOUT);
    }

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    if (initcount > 1) {
        ASSERT_TEST(count == (initcount - 2));
    } else {
        ASSERT_TEST(count == 0);
    }

    result = cy_rtos_set_semaphore(sem, false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    if (initcount > 1) {
        ASSERT_TEST(count == (initcount - 1));
    } else {
        ASSERT_TEST(count == 1);
    }

    result = cy_rtos_set_semaphore(sem, false);
    //ASSERT_TEST(result == CY_RSLT_SUCCESS);   // RT-Thread
    if (maxcount > 1) {
        ASSERT_TEST(result == CY_RSLT_SUCCESS);
    } else {
        ASSERT_TEST(result == CY_RTOS_GENERAL_ERROR);
    }

    result = cy_rtos_get_count_semaphore(sem, &count);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    //ASSERT_TEST(count == initcount);
    if (initcount >= 1) {
        ASSERT_TEST(count == initcount);
    } else {
        ASSERT_TEST(count == 2);
    }

    return NULL;
}

static const char *run_semaphore_tests(void)
{
    size_t peak_start, mem_start;
    size_t peak_end, mem_end;

    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_start, &mem_start);

    cy_semaphore_t semaphore;
    uint32_t maxcount, initcount;

    maxcount = 1;
    initcount = 1;
    RUN_TEST(test_init_semaphore(&semaphore, maxcount, initcount));
    RUN_TEST(test_get_set_semaphore(&semaphore, maxcount, initcount));
    RUN_TEST(test_get2_set2_semaphore(&semaphore, maxcount, initcount));
    RUN_TEST(test_deinit_semaphore(&semaphore));

    cy_semaphore_t semaphore2;
    maxcount = 2;
    initcount = 2;
    RUN_TEST(test_init_semaphore(&semaphore2, maxcount, initcount));
    RUN_TEST(test_get_set_semaphore(&semaphore2, maxcount, initcount));
    RUN_TEST(test_get2_set2_semaphore(&semaphore2, maxcount, initcount));
    RUN_TEST(test_deinit_semaphore(&semaphore2));

    cy_semaphore_t semaphore3;
    maxcount = 1;
    initcount = 0;
    RUN_TEST(test_init_semaphore(&semaphore3, maxcount, initcount));
    RUN_TEST(test_get_set_semaphore(&semaphore3, maxcount, initcount));
    RUN_TEST(test_deinit_semaphore(&semaphore3));

    cy_semaphore_t semaphore4;
    maxcount = 2;
    initcount = 0;
    RUN_TEST(test_init_semaphore(&semaphore4, maxcount, initcount));
    RUN_TEST(test_get2_set2_semaphore(&semaphore4, maxcount, initcount));
    RUN_TEST(test_deinit_semaphore(&semaphore4));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_end, &mem_end);
    RUN_TEST(test_mem_leak(mem_start, mem_end));

    return NULL;
}

#endif

#if DO_EVENT_TESTS
static const char *test_init_event(cy_event_t* event)
{
    cy_rslt_t result;

    result = cy_rtos_init_event(event);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_deinit_event(cy_event_t* event)
{
    cy_rslt_t result;

    result = cy_rtos_deinit_event(event);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

const uint32_t USABLE_BITS = 0x00FFFFFF;    // some bits are 'reserved' for FreeRTOS kernel

#if 1
const uint32_t CONNECT_BIT = BIT0;
const uint32_t ABORT_BIT   = BIT11;
const uint32_t ERROR_BIT   = BIT23;

#else
const uint32_t CONNECT_BIT = BIT0;
const uint32_t ABORT_BIT   = BIT3;
const uint32_t ERROR_BIT   = BIT7;
#endif

static const char *test_get_set_bits_event2(cy_event_t* event,
                                            uint32_t setbits,
                                            uint32_t waitbits,
                                            bool clear_bits_that_caused_return,
                                            bool all_bits_must_be_set)
{
    cy_rslt_t result;
    uint32_t current_bits;
    uint32_t desired_bits;
    bool wait_is_successful;

    DEBUG_ASSERT(waitbits != 0);                      // prevent assertion in FreeRTOS
    DEBUG_ASSERT((setbits  & (~USABLE_BITS)) == 0);   // reserved bits are disallowed in FreeRTOS
    DEBUG_ASSERT((waitbits & (~USABLE_BITS)) == 0);   // reserved bits are disallowed in FreeRTOS

    // check if it's clean
    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    if (current_bits != 0) {
        // if it's not clean, clear the bits
        result = cy_rtos_clearbits_event(event, USABLE_BITS, false);
        ASSERT_TEST(result == CY_RSLT_SUCCESS);

        // verify it's clean
        result = cy_rtos_getbits_event(event, &current_bits);
        ASSERT_TEST(result == CY_RSLT_SUCCESS);
        ASSERT_TEST(current_bits == 0);

        // clearing the bits when already 'clean', should produce an error
        result = cy_rtos_clearbits_event(event, USABLE_BITS, false);
        ASSERT_TEST(result == CY_RTOS_GENERAL_ERROR);
    }

    // now we're in a clean slate

    // wait for something that has not happened -> timeout
    desired_bits = waitbits;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RTOS_TIMEOUT);
    ASSERT_TEST(desired_bits == 0);  // no bits associated with the event

    // trigger an event, then wait -> success maybe (depends on waitbits, setbits and all_bits_must_be_set)
    result = cy_rtos_setbits_event(event, setbits, false);
    ASSERT_TEST(result == ((setbits == 0)? CY_RTOS_GENERAL_ERROR : CY_RSLT_SUCCESS));

    wait_is_successful = false;
    desired_bits = waitbits;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);

    if ((setbits & waitbits) > 0) {
        // waitbits include something in setbits -> at least 1 event should have happened

        //if (all_bits_must_be_set || (setbits == waitbits)) {
        if (((setbits & waitbits) == waitbits) || (!all_bits_must_be_set)) {
            // success
            // all events waited for has happened, or
            // caller did not insist on waiting for all events
            ASSERT_TEST(result == CY_RSLT_SUCCESS);
            ASSERT_TEST(desired_bits == setbits); // return the bits associated with the event that happened
            wait_is_successful = true;

        } else {
            // caller wanted to wait for more events, than has actually happened
            ASSERT_TEST(result == CY_RTOS_TIMEOUT);
            ASSERT_TEST(desired_bits == setbits); // return the bits associated with the event that happened
        }

    } else {
        // did not wait for the right event -> fail
        ASSERT_TEST(result == CY_RTOS_TIMEOUT);
        ASSERT_TEST(desired_bits == setbits); // return the bits associated with the event that happened
    }

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    if (wait_is_successful) {
        if (clear_bits_that_caused_return) {
            uint32_t expected_bits = (~waitbits) & setbits; // triggered event has been cleared
            ASSERT_TEST(current_bits == expected_bits);
        } else {
            ASSERT_TEST(current_bits == setbits); // triggered event is still remembered
        }

    } else {
        ASSERT_TEST(current_bits == setbits); // triggered event is still remembered
    }

    // before leaving, put us back to a clean slate
    if (current_bits != 0) {
        // if it's not clean, clear the bits
        result = cy_rtos_clearbits_event(event, USABLE_BITS, false);
        ASSERT_TEST(result == CY_RSLT_SUCCESS);

        // verify it's clean
        result = cy_rtos_getbits_event(event, &current_bits);
        ASSERT_TEST(result == CY_RSLT_SUCCESS);
        ASSERT_TEST(current_bits == 0);

        // clearing the bits when already 'clean', should produce an error
        result = cy_rtos_clearbits_event(event, USABLE_BITS, false);
        ASSERT_TEST(result == CY_RTOS_GENERAL_ERROR);
    }

    return NULL;
}

static const char *test_get_set_bits_event(cy_event_t* event)
{
    cy_rslt_t result;
    uint32_t current_bits;
    uint32_t desired_bits;
    bool clear_bits_that_caused_return;
    bool all_bits_must_be_set;

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == 0);

    desired_bits = CONNECT_BIT;
    clear_bits_that_caused_return = true;
    all_bits_must_be_set = true;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RTOS_TIMEOUT);
    ASSERT_TEST(desired_bits == 0);  // no bits associated with the event

    result = cy_rtos_setbits_event(event, CONNECT_BIT, false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    desired_bits = CONNECT_BIT;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(desired_bits == CONNECT_BIT); // return the bits associated with the event

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == 0); // bits cleared when cy_rtos_waitbits_event returned success

    result = cy_rtos_setbits_event(event, (CONNECT_BIT | ERROR_BIT), false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    desired_bits = CONNECT_BIT;
    clear_bits_that_caused_return = false;  // don't clear
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(desired_bits == (CONNECT_BIT | ERROR_BIT)); // return the bits associated with the event

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == (CONNECT_BIT | ERROR_BIT)); // bits not cleared

    result = cy_rtos_clearbits_event(event, CONNECT_BIT, false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == ERROR_BIT);

    result = cy_rtos_setbits_event(event, ABORT_BIT, false);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == (ABORT_BIT | ERROR_BIT));

    desired_bits = ABORT_BIT;
    clear_bits_that_caused_return = true;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(desired_bits == (ABORT_BIT | ERROR_BIT)); // return the bits associated with the event

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == ERROR_BIT); // only ABORT bit is cleared

    desired_bits = ABORT_BIT | ERROR_BIT;
    clear_bits_that_caused_return = true;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RTOS_TIMEOUT);
    ASSERT_TEST(desired_bits == ERROR_BIT);   // return the bits associated with the event

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == ERROR_BIT); // ERROR bit is not cleared

    desired_bits = ABORT_BIT | ERROR_BIT;
    all_bits_must_be_set = false;
    result = cy_rtos_waitbits_event(   event,
                                       &desired_bits,
                                       clear_bits_that_caused_return,
                                       all_bits_must_be_set,
                                       WAIT_FOR_EVENT_MSEC);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(desired_bits == ERROR_BIT);   // return the bits associated with the event

    result = cy_rtos_getbits_event(event, &current_bits);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(current_bits == 0);

    return NULL;
}

static const char *run_event_tests(void)
{
    size_t peak_start, mem_start;
    size_t peak_end, mem_end;

    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_start, &mem_start);

    cy_event_t event;

    RUN_TEST(test_init_event(&event));
    RUN_TEST(test_get_set_bits_event(&event));
#if 1
    DEBUG_PRINT(("[%d] 0-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, 0, CONNECT_BIT, true, true));

    DEBUG_PRINT(("[%d] 1-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT, true, true));
    DEBUG_PRINT(("[%d] 1-bit, 1-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT, false, true));
    DEBUG_PRINT(("[%d] 1-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 1-bit, 1-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, ERROR_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 1-bit, 2-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 1-bit, 2-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT, false, true));
    DEBUG_PRINT(("[%d] 1-bit, 2-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 1-bit, 2-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 2-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT, true, true));
    DEBUG_PRINT(("[%d] 2-bit, 1-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT, false, true));
    DEBUG_PRINT(("[%d] 2-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 2-bit, 1-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, ERROR_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 2-bit, 2-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 2-bit, 2-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT, false, true));
    DEBUG_PRINT(("[%d] 2-bit, 2-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 2-bit, 2-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 1-bit, 3-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, true, true));
    DEBUG_PRINT(("[%d] 1-bit, 3-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, false, true));
    DEBUG_PRINT(("[%d] 1-bit, 3-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, true, true));
    DEBUG_PRINT(("[%d] 1-bit, 3-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 2-bit, 3-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, true, true));
    DEBUG_PRINT(("[%d] 2-bit, 3-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, false, true));
    DEBUG_PRINT(("[%d] 2-bit, 3-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, true, true));
    DEBUG_PRINT(("[%d] 2-bit, 3-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 3-bit, 3-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, true, true));
    DEBUG_PRINT(("[%d] 3-bit, 3-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, false, true));
    DEBUG_PRINT(("[%d] 3-bit, 3-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, true, true));
    DEBUG_PRINT(("[%d] 3-bit, 3-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT|ABORT_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 3-bit, 2-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 3-bit, 2-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT, false, true));
    DEBUG_PRINT(("[%d] 3-bit, 2-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT, true, true));
    DEBUG_PRINT(("[%d] 3-bit, 2-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT|ERROR_BIT, false, true));
    print_separator();

    DEBUG_PRINT(("[%d] 3-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT, true, true));
    DEBUG_PRINT(("[%d] 3-bit, 1-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT, false, true));
    DEBUG_PRINT(("[%d] 3-bit, 1-bit, true, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT, true, true));
    DEBUG_PRINT(("[%d] 3-bit, 1-bit, false, true\n", __LINE__));
    RUN_TEST(test_get_set_bits_event2(&event, CONNECT_BIT|ERROR_BIT|ABORT_BIT, CONNECT_BIT, false, true));
    print_separator();
#endif

    RUN_TEST(test_deinit_event(&event));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_end, &mem_end);
    RUN_TEST(test_mem_leak(mem_start, mem_end));

    return NULL;
}
#endif


#if DO_QUEUE_TESTS

typedef struct {
    uint8_t buf[6];
    uint16_t length;
} my_queue_message_t;

static const char *test_init_queue( cy_queue_t* queue,
                                    size_t length,
                                    size_t itemsize)
{
    cy_rslt_t result;

    result = cy_rtos_init_queue(queue, length, itemsize);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_deinit_queue(cy_queue_t* queue)
{
    cy_rslt_t result;

    result = cy_rtos_deinit_queue(queue);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_put_get_queue(  cy_queue_t* queue,
                                        size_t length)
{
    cy_rslt_t result;
    my_queue_message_t message;
    size_t num_waiting;
    size_t num_spaces;

    uint8_t pattern[] = {0xAB, 0xCD, 0xEF};
    int i;

    for (i = 0; i < ARRAY_SIZE(pattern); i++) {
        memset(message.buf, pattern[i], sizeof(message.buf));
        message.length = sizeof(message.buf);

        result = cy_rtos_put_queue( queue,
                                    &message,
                                    0,
                                    false);
        ASSERT_TEST(result == CY_RSLT_SUCCESS);
    }

    result = cy_rtos_count_queue(queue, &num_waiting);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(num_waiting == i);

    result = cy_rtos_space_queue(queue, &num_spaces);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST((num_waiting + num_spaces) == length);

    i = 0;
    do {
        result = cy_rtos_get_queue( queue,
                                    &message,
                                    WAIT_FOR_QUEUE_MSEC,
                                    false);

        if (i < num_waiting) {
            ASSERT_TEST(result == CY_RSLT_SUCCESS);
            ASSERT_TEST(message.buf[0] == pattern[i]);
            ASSERT_TEST(message.length == sizeof(message.buf));

        } else {
            ASSERT_TEST(result == CY_RTOS_GENERAL_ERROR);
            break;
        }

        i++;
    } while (true);

    result = cy_rtos_count_queue(queue, &num_waiting);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(num_waiting == 0);

    // fill up the queue, try to exceed length by 1
    for (i = 0; i < (length + 1); i++) {
        memset(message.buf, 0, sizeof(message.buf));
        message.length = sizeof(message.buf);

        result = cy_rtos_put_queue( queue,
                                    &message,
                                    WAIT_FOR_QUEUE_MSEC,
                                    false);
        if (i < length) {
            ASSERT_TEST(result == CY_RSLT_SUCCESS);
        } else {
            ASSERT_TEST(result == CY_RTOS_GENERAL_ERROR);
        }
    }

    result = cy_rtos_count_queue(queue, &num_waiting);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(num_waiting == length);

    result = cy_rtos_reset_queue(queue);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_count_queue(queue, &num_waiting);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(num_waiting == 0);

    return NULL;
}

static const char *run_queue_tests(void)
{
    size_t peak_start, mem_start;
    size_t peak_end, mem_end;
    size_t length = 10;
    size_t itemsize = sizeof(my_queue_message_t);

    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_start, &mem_start);

    cy_queue_t queue;

    RUN_TEST(test_init_queue(&queue, length, itemsize));
    RUN_TEST(test_put_get_queue(&queue, length));
    RUN_TEST(test_deinit_queue(&queue));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_end, &mem_end);
    RUN_TEST(test_mem_leak(mem_start, mem_end));

    return NULL;
}

#endif

#if DO_TIMER_TESTS

static const char *test_init_timer( cy_timer_t* timer,
                                    cy_timer_trigger_type_t type,
                                    cy_timer_callback_t func,
                                    cy_timer_callback_arg_t arg)
{
    cy_rslt_t result;

    result = cy_rtos_init_timer(timer, type, func, arg);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_deinit_timer(cy_timer_t* timer)
{
    cy_rslt_t result;

    result = cy_rtos_deinit_timer(timer);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    return NULL;
}

static const char *test_start_stop_timer(cy_timer_t* timer,
                                         cy_time_t period_msec,
                                         cy_timer_trigger_type_t type,
                                         int* counter)
{
    cy_rslt_t result;
    bool is_running;
    cy_time_t start_time;
    cy_time_t end_time;
    int wait_interval = (type == CY_TIMER_TYPE_PERIODIC)? 3 : 2;

    result = cy_rtos_is_running_timer(timer, &is_running);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(is_running == false);

    result = cy_rtos_start_timer(timer, period_msec);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_is_running_timer(timer, &is_running);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(is_running == true);

    result = cy_rtos_get_time(&start_time);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    DEBUG_PRINT(("start_time = %lu\n", start_time));

    result = cy_rtos_delay_milliseconds(wait_interval * period_msec);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    if (type == CY_TIMER_TYPE_PERIODIC) {
        ASSERT_TEST(*counter >= wait_interval);

    } else if (type == CY_TIMER_TYPE_ONCE) {
        ASSERT_TEST(*counter == 1);

    } else {
        DEBUG_ASSERT(0);
    }

    result = cy_rtos_is_running_timer(timer, &is_running);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(is_running == (type == CY_TIMER_TYPE_PERIODIC));

    result = cy_rtos_stop_timer(timer);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);

    result = cy_rtos_is_running_timer(timer, &is_running);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    ASSERT_TEST(is_running == false);

    result = cy_rtos_get_time(&end_time);
    ASSERT_TEST(result == CY_RSLT_SUCCESS);
    DEBUG_PRINT(("end_time = %lu\n", end_time));
    DEBUG_PRINT(("elapsed_time = %lu\n", end_time - start_time));
    ASSERT_TEST((end_time - start_time)/1000 == wait_interval);

    return NULL;
}

static void test_timer_callback(cy_timer_callback_arg_t arg)
{
    int *counter = (int *)arg;
    DEBUG_ASSERT(counter != NULL);
    *counter += 1;
}

static const char *run_timer_tests(void)
{
    size_t peak_start, mem_start;
    size_t peak_end, mem_end;
    int counter;

    int i;
    cy_timer_trigger_type_t timer_types[] = {CY_TIMER_TYPE_PERIODIC, CY_TIMER_TYPE_ONCE};
    cy_timer_callback_t timer_func = test_timer_callback;

    DEBUG_PRINT(("%s [%d]\n", __FUNCTION__, __LINE__));

    CY_MEMTRACK_MALLOC_STATS_EX(&peak_start, &mem_start);

    for (i = 0; i < ARRAY_SIZE(timer_types); i++) {
        cy_timer_t timer;

        counter = 0;

        DEBUG_PRINT(("%s\n", (timer_types[i] == CY_TIMER_TYPE_PERIODIC)?
                "PERIODIC" : "ONE_SHOT"));

        RUN_TEST(test_init_timer(&timer,
                                 timer_types[i],
                                 timer_func,
                                 (cy_timer_callback_arg_t)&counter));

        RUN_TEST(test_start_stop_timer( &timer,
                                        WAIT_FOR_TIMER_MSEC,
                                        timer_types[i],
                                        &counter));

        RUN_TEST(test_deinit_timer(&timer));
    }


    CY_MEMTRACK_MALLOC_STATS_EX(&peak_end, &mem_end);
    RUN_TEST(test_mem_leak(mem_start, mem_end));

    return NULL;
}
#endif


static const char *run_all_tests(void)
{
#if DO_THREAD_TESTS
    // invokes: exit_thread, terminate_thread, join_thread
    // e.g. wifi-connection-manager/latest-v2.X/source/COMPONENT_WPS/cy_wps.c
    // e.g. wifi-mw-core/experimental-v3.1.0.1/lwip-whd-port/cy_lwip_dhcp_server.c
    RUN_TEST(run_thread_tests(TEST_ARG_CALL_EXIT_THREAD_AND_RETURN, TEST_ARG_CALL_TERMINATE));
    print_separator();

    // no such e.g.
    RUN_TEST(run_thread_tests(TEST_ARG_CALL_EXIT_THREAD_AND_LOOP, TEST_ARG_CALL_TERMINATE));
    print_separator();

    // invokes: terminate_thread, join_thread
    // e.g. source/mqtt_task.c
    // e.g. mqtt/latest-v3.X/source/cy_mqtt_api.c
    RUN_TEST(run_thread_tests(TEST_ARG_SKIP_EXIT_THREAD_AND_LOOP, TEST_ARG_CALL_TERMINATE));
    print_separator();

    // invokes: exit_thread, join_thread
    // e.g. abstraction-rtos/experimental-v1.4.0.2/source/cy_worker_thread.c
    // e.g. wifi-host-driver/release-v1.94.0/WiFi_Host_Driver/src/whd_thread.c
    RUN_TEST(run_thread_tests(TEST_ARG_CALL_EXIT_THREAD_AND_RETURN, TEST_ARG_SKIP_TERMINATE));
    print_separator();

    // no such e.g.
    RUN_TEST(run_thread_tests(TEST_ARG_CALL_EXIT_THREAD_AND_LOOP, TEST_ARG_SKIP_TERMINATE));
    print_separator();
#endif

#if DO_MUTEX_TESTS
    RUN_TEST(run_mutex_tests(1));
    print_separator();
#endif

#if DO_SEMAPHORE_TESTS
    RUN_TEST(run_semaphore_tests());
    print_separator();
#endif

#if DO_EVENT_TESTS
    RUN_TEST(run_event_tests());
    print_separator();
#endif

#if DO_QUEUE_TESTS
    RUN_TEST(run_queue_tests());
    print_separator();
#endif

#if DO_TIMER_TESTS
    RUN_TEST(run_timer_tests());
    print_separator();
#endif

    return NULL;
}

/*-- Public Functions -------------------------------------------------*/

int unit_test_rtos_main(void)
{
    const char *fail_msg;

    fail_msg = run_all_tests();
    DEBUG_PRINT(("\n%s, tests run: %d\n",
                 fail_msg ? "FAIL" : "PASS", s_num_tests));

    return fail_msg == NULL ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif
