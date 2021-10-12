/*******************************************************************************
* File Name: cy_notification.c
*
* Description: This file contains functions that emulates xTaskNotify
*
* Related Document: See README.md
*
*
*******************************************************************************
* Copyright 2020-2021, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
*
* This software, including source code, documentation and related
* materials ("Software") is owned by Cypress Semiconductor Corporation
* or one of its affiliates ("Cypress") and is protected by and subject to
* worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software
* source code solely for use in connection with Cypress's
* integrated circuit products.  Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*******************************************************************************/

#include "cy_notification.h"


/*******************************************************************************
 * Public Functions
 ******************************************************************************/

cy_rslt_t cy_notification_init(cy_notification_t *notification,
                               uint32_t initial_notification_value)
{
    cy_rslt_t status;

    if (notification == NULL)
        return (CY_RTOS_BAD_PARAM);

    memset(notification, 0, sizeof(*notification));

    status = cy_rtos_init_semaphore(&notification->sem, 1, 0);

    if (status == CY_RSLT_SUCCESS) {
        notification->value = initial_notification_value;
    }

    return status;
}

cy_rslt_t cy_notification_deinit(cy_notification_t *notification)
{
    cy_rslt_t status;

    if (notification == NULL)
        return (CY_RTOS_BAD_PARAM);

    status = cy_rtos_deinit_semaphore(&notification->sem);
    memset(notification, 0, sizeof(*notification));

    return status;
}

cy_rslt_t cy_notification_wait(cy_notification_t *notification,
                               uint32_t bits_to_clear_on_entry,
                               uint32_t bits_to_clear_on_exit,
                               uint32_t *notification_value,
                               cy_time_t timeout_ms)
{
    cy_rslt_t status;

    if ((notification == NULL) || (notification_value == NULL))
        return (CY_RTOS_BAD_PARAM);

    notification->value &= ~bits_to_clear_on_entry;

    status = cy_rtos_get_semaphore(&notification->sem, timeout_ms, false);

    if (status == CY_RSLT_SUCCESS) {
        *notification_value = notification->value;
        notification->value &= ~bits_to_clear_on_exit;
    }

    return status;
}

cy_rslt_t cy_notification_set(cy_notification_t *notification,
                              uint32_t new_notification_value,
                              bool in_isr)
{
    if (notification == NULL)
        return (CY_RTOS_BAD_PARAM);

    notification->value = new_notification_value;

    return cy_rtos_set_semaphore(&notification->sem, in_isr);
}

/* [] END OF FILE */
