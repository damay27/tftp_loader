#include "pico/cyw43_arch.h"
#include "pico/sync.h"
#include "hardware/flash.h"
#include "hardware/sync.h"

#include "tftp.h"

/*
 * Erease the flash sector at the given offset.
 *
 * Parameters:
 *  offset: Absolute offset to the sector to be erased.
 *          NOTE: This is an absolute address NOT the offset
 *                from the start of flash.
 *
 * Return:
 *  Nothing.
 */
void _flash_sector_erase(uint32_t offset) {
    uint32_t interrupt_status = save_and_disable_interrupts();
    flash_range_erase(offset, FLASH_SECTOR_SIZE);
    restore_interrupts(interrupt_status);
}

/*
 * Write a block of data to flash.
 *
 * Parameters:
 *  block_len: Length of the block to be written.
 *  tftp_data: Pointer to the data to be written.
 *  current_byte_count: Number of bytes written to flash so far.
 *
 * Return:
 *  Nothing.
 */
void _write_block(uint16_t block_len,
                    uint8_t *tftp_data, uint32_t current_byte_count) {
    uint8_t block[2*FLASH_PAGE_SIZE] = {0};
    memset(block, 0, 2*FLASH_PAGE_SIZE);
    memcpy(block, tftp_data, block_len);

    /* Check if we are on a sector boundry. */
    if ( (FLASH_OFFSET + current_byte_count) % FLASH_SECTOR_SIZE == 0) {
        _flash_sector_erase(FLASH_OFFSET + current_byte_count);
    }

    uint32_t interrupt_status = save_and_disable_interrupts();
    flash_range_program(FLASH_OFFSET +current_byte_count, block, 2*FLASH_PAGE_SIZE);
    restore_interrupts(interrupt_status);
}

/*
 * Reset the tftp_net_data structure values that are realted to
 * the TFTP session. Note that we don't reset the flash_modified
 * boolean since we want to keep that data in between sessions.
 *
 * Parameters:
 *  net_data: The tftp_net_data structure to reset.
 *
 * Return:
 *  Nothing.
 */
void _reset_tftp_session(struct tftp_net_data *net_data) {
    net_data->dst_port = 69;
    net_data->flash_byte_count = 0;
    net_data->block_count = 1;
    sem_init(&net_data->updated_done, 0, 1);
}

/*
 * Send a generic UDP packet using the src/dst ports and dst IP from the tftp_net_data
 * struct.
 *
 * Parameters:
 *  net_data    -> tftp_net_data struct where the destination port andIP address and pcb are pulled from.
 *  data_buffer -> Buffer of data to be sent.
 *  buffer_len  -> Size of the data buffer.
 *
 * Return:
 *  
 */
int _send_udp_packet(struct tftp_net_data *net_data, uint8_t *data_buffer, uint16_t buffer_size) {
    int return_code = 0;
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, buffer_size, PBUF_RAM);
    memset((char*)p->payload, 0, buffer_size);
    memcpy((char*)p->payload, data_buffer, buffer_size);

    err_t er = udp_sendto(net_data->pcb, p, &net_data->srv_ip_addr, net_data->dst_port);
    if (er != ERR_OK) {
        return_code = -1;
    }

    pbuf_free(p);
    return return_code;
}

/*
 * Send a TFTP read request packet.
 *
 * Parameters:
 * net_data -> tftp_net_data struct to pull the destination
 *             IP and port from.
 *
 * Return:
 *  Nothing.
 */
static inline void _send_rrq(struct tftp_net_data *net_data) {
    
    /* This packets content is completely known at compile time. */
    static uint8_t rrq_packet[] =  "\x0\x1" FILE_NAME "octet";
    _send_udp_packet(net_data, rrq_packet, sizeof(rrq_packet));
}

/*
 * Send a TFTP error packet.
 *
 * Parameters:
 *  net_data -> Data structure that the dst IP and port are pulled from.
 *  err_code -> TFTP error code to put in the packet.
 *
 * Return:
 *  Nothing.
*/
static inline void _send_err(struct tftp_net_data *net_data, uint8_t err_code) {
    static const char err_msg[] = "TFTP LOADER ERROR";
    uint8_t err_data[4 + sizeof(err_msg)] = {0, 5};
    err_data[3] = lwip_htons(err_code) >> 8;
    err_data[4] = lwip_htons(err_code) & 0xFF;
    memcpy(err_data + 4, err_msg, sizeof(err_msg));

    _send_udp_packet(net_data, err_data, sizeof(err_data));
}

/*
 * Send a TFTP ack packet for a given block ID.
 *
 * Parameters:
 *  net_data -> Data structure that the dst IP and port are pulled from.
 *  block_id -> The TFTP block ID you are acking.
 *
 * Return:
 *  Nothing.
*/
static inline void _send_ack(struct tftp_net_data *net_data, uint16_t block_id) {
    uint16_t ack_data[2] = {lwip_htons(TFTP_ACK), lwip_htons(block_id)};

    // printf("ACK %u\n", block_id);
    _send_udp_packet(net_data, (uint8_t*)ack_data, sizeof(ack_data));
}

/* Callback function for lwip. */
void udp_receive_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr, uint16_t port)
{
    struct tftp_net_data *net_data = (struct tftp_net_data*) arg;
    /*
     * Make the destination port (the one we send packets to) to
     * be the same as the remote port we are receiving data from.
     */
    if (net_data->dst_port == 69)
        net_data->dst_port = port;

    /* Check if the packet is from the IP and port we expect. */
    if (net_data->dst_port != port || !ip_addr_cmp(&net_data->srv_ip_addr, addr)) {
        pbuf_free(p);
        return;
    }

    /* Extract the TFTP packets opcode form the packet payload. */
    uint16_t received_opcode = ((uint16_t*)p->payload)[0];
    received_opcode = lwip_ntohs(received_opcode);

    uint16_t block_len = p->len - 4;
    uint8_t *tftp_data = ((uint8_t*)p->payload) + 4;
    uint16_t received_block_count = lwip_ntohs(((uint16_t*)p->payload)[1]);

    switch (received_opcode) {
        case TFTP_ERROR:
            printf("TFTP_ERROR: %s\n", p->payload + 4);
            net_data->error_code = ERROR_RECEIVED_ERR_PACKET;
            goto ERROR_STATE;
            break;

        case TFTP_DATA:
            if (received_block_count <= net_data->block_count) {
                if (received_block_count == net_data->block_count) {
                    _write_block(block_len, tftp_data, net_data->flash_byte_count);
                    net_data->block_count++;
                    net_data->flash_modified = true;
                    net_data->flash_byte_count += block_len;
                }
                // send ack. might be resending for rbc < bc
                _send_ack(net_data, received_block_count);
            }
            else {
                _send_err(net_data, 0);
                net_data->error_code = ERROR_INVALID_BLOCK_ID;
                goto ERROR_STATE;
            }
            break;

        default:
            _send_err(net_data, 0);
            net_data->error_code = ERROR_UNKNOWN_OPCODE;
            goto ERROR_STATE;
    }
    /*
     * The end of a transfer is signaled by a block
     * with will that 512 bytes in it.
     */
    if (block_len < 512) {
        sem_release(&net_data->updated_done);
    }

    pbuf_free(p);
    net_data->error_code = 0;
    return;

ERROR_STATE:
    pbuf_free(p);
    sem_release(&net_data->updated_done);
    return;
}

/*
 * Fill in the net_data struct and assign the receive callback.
 *
 * Parameters:
 *  net_data    -> tftp_net_data struct to populate.
 *  srv_ip_addr -> IP address of the server to conneect to as a C
 *                 style string.
 *  dst_port    -> Port to send to.
 *
 * Return:
 *  Nothing.
 */
void tftp_net_setup(struct tftp_net_data* net_data, char *srv_ip_addr) {
    /* Initialize the pcb, ip address, and port */
    net_data->pcb = udp_new();
    ipaddr_aton(srv_ip_addr, &net_data->srv_ip_addr);
    /* After the initial tftp handshake this will be overwritten */
    net_data->dst_port = 69;

    sem_init(&net_data->updated_done, 0, 1);

    /* Select a random source port in the range [49152, 65535] */
    net_data->src_port = rand() % 16383 + 49152;
    net_data->flash_byte_count = 0;
    /* TFTP block counts start at 1. */
    net_data->block_count = 1;

    net_data->flash_modified = false;
    net_data->error_code = 0;


    /* Register the udp receive callback. */
    udp_recv(net_data->pcb, udp_receive_callback, net_data);
    // err_t err = udp_bind(net_data->pcb, IP_ANY_TYPE, net_data->src_port);
}

/*
 * Close the UDP socket.
 *
 * Parameters:
 *  net_data -> tftp_net_data used for tracking the socket.
 *
 * Return:
 *  Nothing.
 */
void tftp_net_teardown(struct tftp_net_data *net_data) {
    udp_remove(net_data->pcb);
}

int tftp_flash(struct tftp_net_data *net_data) {

    _reset_tftp_session(net_data);

    err_t err = udp_bind(net_data->pcb, IP_ANY_TYPE, net_data->src_port);
    if (err != ERR_OK) {
        printf("Failed to connect\n");
        return ERROR_CONNECTION;
    }
    
    /* send rrq */
    _send_rrq(net_data);
    
    /*
     * Timeout detection loop.
     * Each timeout duration is what stall counter tick.
     */
    uint32_t previous_block_count = 0;
    uint32_t stall_tick_count = 0;
    while (!sem_acquire_timeout_ms(&net_data->updated_done, STALL_TICK_MS)) {
        
        /*
         * Has the block id counter increased since last time?
         * NOTE: Accessing the block_count member variable is safe here
         * for two reasons.
         *  1. The boot loader runs in a single thread with interrupts so
         *     there is no way for this variable to be modified in two places
         *     at the same time.
         *  2. This will only read the variable.
         */
        if (net_data->block_count > previous_block_count) {
            /*
             * Block count increased so update our previous count and
             * clear the tick counter.
             */
            previous_block_count = net_data->block_count;
            stall_tick_count = 0;
        }
        else {
            /*
             * If there was no increase in block count then increase
             * tick count.
             */
            stall_tick_count++;
        }

        /* If we stall for to long then reset the tftp session. */
        if (stall_tick_count >= STALL_TICK_LIMIT) {
            _send_err(net_data, 0);
            udp_disconnect(net_data->pcb);
            return ERROR_TIMEOUT;
        }
    }

    printf("%u bytes written to flash.\n", net_data->flash_byte_count);

    udp_disconnect(net_data->pcb);

    return net_data->error_code;
}
