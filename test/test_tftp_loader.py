from scapy.all import *
import sys
import socket
import time

def check_tftp_rrq(rrq_packet):
    return rrq_packet.filename == b"PROG.BIN" and rrq_packet.mode == b"octet"

def check_ack(ack_packet, block_id):
    return ack_packet.block == block_id

def check_error(error_packet):
    return error_packet.errorcode == 0 and error_packet.errormsg == b"TFTP LOADER ERROR"

def test_nominal(bin_buffer, tftp_sock, ephemeral_sock):
    # Wait for an RRQ packet
    (packet, addr) = tftp_sock.recvfrom(4096)
    target_ip = addr[0]
    target_port = addr[1]
    rrq_packet = TFTP(packet)[TFTP_RRQ]
    assert(check_tftp_rrq(rrq_packet))
    # Send data packets and wait for ACK.
    index = 0
    block_id = 1
    while index < len(bin_buffer):
        if (index + 512) < len(bin_buffer):
            data_block = bin_buffer[index:index+512]
        else:
            data_block = bin_buffer[index:len(bin_buffer)]

        # Send a data packet
        time.sleep(.01)
        ephemeral_sock.sendto(bytes(TFTP()/TFTP_DATA(block=block_id)/data_block), (target_ip, target_port))

        # Wait for the ack
        timedout = False
        try:
            packet = ephemeral_sock.recv(4096)
        except TimeoutError:
            timedout = True

        # assert(TFTP_ACK in packet)
        if not timedout:
            ack_packet = TFTP(packet)[TFTP_ACK]
            assert(check_ack(ack_packet, block_id))
            block_id += 1
            index += 512

def test_out_of_order_block(bin_buffer, tftp_sock, ephemeral_sock):
    # Wait for an RRQ packet
    (packet, addr) = tftp_sock.recvfrom(4096)

    target_ip = addr[0]
    target_port = addr[1]
    rrq_packet = TFTP(packet)[TFTP_RRQ]
    assert(check_tftp_rrq(rrq_packet))

    # Send data packets and wait for ACK.
    index = 0
    block_id = 1
    while index < len(bin_buffer):
        if (index + 512) < len(bin_buffer):
            data_block = bin_buffer[index:index+512]
        else:
            data_block = bin_buffer[index:len(bin_buffer)]

        # Send a data packet
        time.sleep(.01)
        ephemeral_sock.sendto(bytes(TFTP()/TFTP_DATA(block=block_id)/data_block), (target_ip, target_port))

        # Wait for the ack
        timedout = False
        try:
            packet = ephemeral_sock.recv(4096)
        except TimeoutError:
            timedout = True

        # assert(TFTP_ACK in packet)
        if not timedout:
            if block_id == 20:
                error_packet = TFTP(packet)[TFTP_ERROR]
                assert(check_error(error_packet))
                test_nominal(bin_buffer, tftp_sock, ephemeral_sock)
                break
            else:
                ack_packet = TFTP(packet)[TFTP_ACK]
                assert(check_ack(ack_packet, block_id))
                block_id += 1
                index += 512

        # Skip several block IDs to force an error.
        if block_id == 5:
            block_id = 20

def test_file_not_found(bin_buffer, tftp_sock, ephemeral_sock):
    # Wait for an RRQ packet
    (packet, addr) = tftp_sock.recvfrom(4096)
    target_ip = addr[0]
    target_port = addr[1]
    rrq_packet = TFTP(packet)[TFTP_RRQ]
    assert(check_tftp_rrq(rrq_packet))
    
    errmsg = "File %s not found on the server." % rrq_packet.filename.decode("utf-8")
    err_packet = TFTP()/TFTP_ERROR(errorcode=1, errormsg=errmsg)
    ephemeral_sock.sendto(bytes(err_packet), (target_ip, target_port))

def test_unknown_opcode(bin_buffer, tftp_sock, ephemeral_sock):
    # Wait for an RRQ packet
    (packet, addr) = tftp_sock.recvfrom(4096)
    target_ip = addr[0]
    target_port = addr[1]
    rrq_packet = TFTP(packet)[TFTP_RRQ]
    assert(check_tftp_rrq(rrq_packet))
    

    incorrect_data = [50, 60, 70 , 80, 90, 100]
    ephemeral_sock.sendto(bytes(incorrect_data), (target_ip, target_port))

def test_rrq_timeout(bin_buffer, tftp_sock, ephemeral_sock):
    # Wait for an RRQ packet and don't respond to it so a timeout occurs.
    (packet, addr) = tftp_sock.recvfrom(4096)
    target_ip = addr[0]
    target_port = addr[1]
    rrq_packet = TFTP(packet)[TFTP_RRQ]
    assert(check_tftp_rrq(rrq_packet))

def test_data_timeout(bin_buffer, tftp_sock, ephemeral_sock):
    # Wait for an RRQ packet
    (packet, addr) = tftp_sock.recvfrom(4096)

    target_ip = addr[0]
    target_port = addr[1]
    rrq_packet = TFTP(packet)[TFTP_RRQ]
    assert(check_tftp_rrq(rrq_packet))

    # Send data packets and wait for ACK.
    index = 0
    block_id = 1
    while index < len(bin_buffer):
        if (index + 512) < len(bin_buffer):
            data_block = bin_buffer[index:index+512]
        else:
            data_block = bin_buffer[index:len(bin_buffer)]

        # Send a data packet
        time.sleep(.01)
        ephemeral_sock.sendto(bytes(TFTP()/TFTP_DATA(block=block_id)/data_block), (target_ip, target_port))

        # Wait for the ack
        timedout = False
        try:
            packet = ephemeral_sock.recv(4096)
        except TimeoutError:
            timedout = True

        # assert(TFTP_ACK in packet)
        if not timedout:
            ack_packet = TFTP(packet)[TFTP_ACK]
            assert(check_ack(ack_packet, block_id))
            block_id += 1
            index += 512

        # On the 5th block ID sleep for a long time to force a timeout
        if block_id == 5:
            time.sleep(10.2)
            error_packet = ephemeral_sock.recv(4096)
            error_packet = TFTP(error_packet)[TFTP_ERROR]
            assert(check_error(error_packet))
            test_nominal(bin_buffer, tftp_sock, ephemeral_sock)
            break

if __name__ == "__main__":

    bin_buffer = []

    # Print the help message if no arguments were given or on of
    # the help flags was used.
    if ((len(sys.argv) == 1) or (sys.argv[1] == "-h" or sys.argv[1] == "--help")):
        print("python3 ./test_tftp_loader <binary file> <test index>")
        print("Each test along with its index is listed below:")
        print("\t0. Testing nominal")
        print("\t1. Testing out of order block")
        print("\t2. Test file not found")
        print("\t3. Test unknown opcode")
        print("\t4. Test RRQ timeout")
        print("\t5. Test DATA timeout")
        exit(0)
    
    try:
        with open(sys.argv[1], "rb") as bin_file:
            bin_buffer = bin_file.read()
    except FileNotFoundError:
        print("ERROR: File not found.")
        exit(-1)

    if (len(sys.argv) > 2):
        try:
            test_index = int(sys.argv[2])
        except:
            print("ERROR: Test index must be an integer.")
            exit(-1)
    else:
        test_index = 0


    tftp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tftp_sock.bind(("", 69))

    ephemeral_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ephemeral_sock.settimeout(5)

    print("Power cycle the board to continue.")
    if test_index == 0:
        print("Testing nominal")
        test_nominal(bin_buffer, tftp_sock, ephemeral_sock)
    elif test_index == 1:
        print("Testing out of order block")
        test_out_of_order_block(bin_buffer, tftp_sock, ephemeral_sock)
    elif test_index == 2:
        print("Test file not found")
        test_file_not_found(bin_buffer, tftp_sock, ephemeral_sock)
    elif test_index == 3:
        print("Test unknown opcode")
        test_unknown_opcode(bin_buffer, tftp_sock, ephemeral_sock)
    elif test_index == 4:
        print("Test RRQ timeout")
        test_rrq_timeout(bin_buffer, tftp_sock, ephemeral_sock)
    elif test_index == 5:
        print("Test DATA timeout")
        test_data_timeout(bin_buffer, tftp_sock, ephemeral_sock)

    # test_nominal(bin_buffer, tftp_sock, ephemeral_sock)
    # test_out_of_order_block(bin_buffer, tftp_sock, ephemeral_sock)
    # test_file_not_found(bin_buffer, tftp_sock, ephemeral_sock)
    # test_unknown_opcode(bin_buffer, tftp_sock, ephemeral_sock)
    # test_rrq_timeout(bin_buffer, tftp_sock, ephemeral_sock)
    # test_data_timeout(bin_buffer, tftp_sock, ephemeral_sock)

