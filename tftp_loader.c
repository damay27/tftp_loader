/*
 * TFTP bootloader for the Raspberry Pi Pico W.
 * Dedicated to the memory of the USS Scorpion SSN-589.
 * Author: Daniel May
 */


#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/structs/scb.h"

#include "tftp.h"

void setup_wifi() {
    if (cyw43_arch_init()) {
        printf("Failed WIFI init\n");
    }
    cyw43_arch_enable_sta_mode();

    if(cyw43_arch_wifi_connect_blocking(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK)) {
        printf("Failed to connect\n");
    }
}

int main() {
    stdio_init_all();
    printf("Starting tftp_loader...\n");
    setup_wifi();

    struct tftp_net_data net_data;
    tftp_net_setup(&net_data, TFTP_SRV_ADDR);

    int status;
    bool retry = false;
    do {
        status = tftp_flash(&net_data);

        if (status == ERROR_RECEIVED_ERR_PACKET) {
            printf("Received error packet from the TFTP server.\n");
        }
        else if (status == ERROR_INVALID_BLOCK_ID) {
            printf("Received invalid block ID.\n");
        }
        else if (status == ERROR_UNKNOWN_OPCODE) {
            printf("Received unknown TFTP opcode.\n");
        }
        else if (status == ERROR_CONNECTION) {
            printf("Error binding to socket.\n");
        }
        else if (status == ERROR_TIMEOUT) {
            printf("Timeout reached.\n");
        }


        retry = status != 0 && net_data.flash_modified;
        if (retry) {
            printf("Flash modified. Retrying download.\n");
        }

    /*
     * If we modified the application stored in flash and then hit an error we 
     * we have probably left the application in a corrupted state so we should
     * again to pull a fresh application binary.
     */
    } while (retry);

    tftp_net_teardown(&net_data);

    // Reboot
    printf("Booting into the application...\n");
    sleep_ms(1000);

    cyw43_arch_deinit();
    scb_hw->vtor = NEW_VTABLE;
    asm volatile (
            // r0 -> stack pointer, r1 -> reset handler
            "ldmia %0!, {r0, r1}\n"
            "msr msp, r0\n"
            "bx r1\n" 
            :
            : "r" (NEW_VTABLE)
        );

    /* This will never be reached. */
    return 0;
}
