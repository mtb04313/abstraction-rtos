/*******************************************************************************
* File Name: cy_unit_test_helper.h
*
* Description: This file defines helper macros for test files
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

#ifndef SOURCE_CY_UNIT_TEST_HELPER_H_
#define SOURCE_CY_UNIT_TEST_HELPER_H_

#ifdef __cplusplus
extern "C"
{
#endif


/*-- Public Definitions -------------------------------------------------*/

#define FAIL(str, line)                                        \
    do {                                                       \
        fprintf(stderr, "Fail on line %d: [%s]\n", line, str); \
        return str;                                            \
    } while (0)

#define ASSERT_TEST(expr)                   \
    do {                                    \
        s_num_tests++;                      \
        if (!(expr)) FAIL(#expr, __LINE__); \
    } while (0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define RUN_TEST(test)            \
    do {                          \
        const char *msg = test;   \
        if (msg) return msg;      \
    } while (0)


/*-- Local Data -------------------------------------------------*/
static int s_num_tests = 0;


#ifdef __cplusplus
}
#endif

#endif // SOURCE_CY_UNIT_TEST_HELPER_H_
