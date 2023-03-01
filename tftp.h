#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>

#include "pico/sync.h"

#define TFTP_RRQ    0x0001
#define TFTP_WRP    0x0002
#define TFTP_DATA   0x0003
#define TFTP_ACK    0x0004
#define TFTP_ERROR  0x0005

/*
 * In cases where we get an error while pulling a new application binary
 * we will take different actions depending on if the application region
 * of flash has been modified. If it was then we have probably already
 * corrupted whatever application was there before so the correct course
 * of action is to attempt to pull the application again. If however we
 * haven't modified the application in flash then we can simply boot
 * into the application like normal.
 */
#define ERROR_RECEIVED_ERR_PACKET   -1
#define ERROR_INVALID_BLOCK_ID      -2
#define ERROR_UNKNOWN_OPCODE        -3
#define ERROR_CONNECTION            -4
#define ERROR_TIMEOUT               -5

/*
 * Offset from the start of flash memory where the downloaded
 * program will be placed.
*/
#define FLASH_OFFSET (512 * 1024)

/*
 * Absolute address (not offset with in flash) where the new applications
 * vector table will be located.
*/
#define NEW_VTABLE (XIP_BASE + FLASH_OFFSET + 0x100)

#ifndef TFTP_SRV_ADDR
#define TFTP_SRV_ADDR "192.168.86.45"
#endif

#ifndef FILENAME
#define FILE_NAME "PROG.BIN\0"
#endif

#define STALL_TICK_MS 500
#define STALL_TICK_LIMIT 20

struct tftp_net_data {
    struct udp_pcb *pcb;

    // Send data
    ip_addr_t srv_ip_addr;
    uint16_t dst_port;

    // Receive data
    semaphore_t updated_done;
    ip_addr_t src_ip_addr;
    uint16_t src_port;
    struct pbuf *packet_buffer;
    uint32_t flash_byte_count;
    uint32_t block_count;

    bool flash_modified;
    int error_code;
};

void tftp_net_setup(struct tftp_net_data* net_data, char *srv_ip_addr);
void tftp_net_teardown(struct tftp_net_data *data);
int tftp_flash(struct tftp_net_data *net_data);

#endif