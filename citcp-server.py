# Yevhen Voitiuk

import argparse, socket, logging
import random
import struct

# Comment out the line below to not print the INFO messages
logging.basicConfig(level=logging.INFO)

BUFFER_SIZE = 24  # Bytes to send at once
HEADER_SIZE = 9  # 9 in bytes, 72 in bits

SEQ_POSITION = 0
SEQ_LENGTH = 16

ACK_POSITION = 16
ACK_LENGTH = 16

WIN_POSITION = 32
WIN_LENGTH = 16

CHECKSUM_POSITION = 48
CHECKSUM_LENGTH = 16

FLAGS_POSITION = 64
FLAGS_LENGTH = 8

# Shortcut for flag values
ACK = 4
SYN = 2
FIN = 1
SYNACK = 6

# ! for network style indian (Big or small idk)
# H is for 2 bytes (unsigned short)
# B is for 1 byte (unsinged char that is represented in int in Python)
MESSAGE_FORMAT = "!HHHHB"


def calculate_checksum(seq_num, ack_num, window_size, flags, payload):

    checksum = seq_num  # Guaranteed not to overflow as seq_num and checksum are both 2 bytes

    checksum += ack_num
    if checksum & 0x0000 != 0:
        checksum += checksum >> ACK_LENGTH

    checksum += window_size
    if checksum & 0x0000 != 0:
        checksum += checksum >> WIN_LENGTH

    checksum += flags
    if checksum & 0x0000 != 0:
        checksum += checksum >> FLAGS_LENGTH

    i = 0
    if len(payload) >= 2:
        while i < len(payload):
            if (len(payload) - i) < 2:
                checksum += ord(payload[i])
            else:
                checksum += ord((payload[i]))
                checksum += ord((payload[i + 1]))
            i += 2
            if checksum & 0x0000 != 0:
                checksum += checksum >> 16
    elif 1 >= len(payload) > 0:
        checksum += ord(payload[0])
        if checksum & 0x0000 != 0:
            checksum += checksum >> 16

    return checksum


def make_message(seq_num, ack_num, window_size, checksum, flags):
    return struct.pack(MESSAGE_FORMAT, seq_num, ack_num, window_size, checksum, flags)


def break_down(file_bytes):
    byte_iter = 0
    packet_list = []
    while byte_iter < len(file_bytes):
        if (len(file_bytes) - byte_iter) < BUFFER_SIZE:
            packet_list.append(file_bytes[byte_iter:len(file_bytes) - byte_iter])
        packet_list.append(file_bytes[byte_iter:byte_iter + BUFFER_SIZE])
        byte_iter += BUFFER_SIZE
    return packet_list



def __init__(self, address, socket):
    self.addr = address
    self.csock = socket
    logging.info('New connection added.')


def server():
    client_addr = ('', 0)
    file_packet_list = []

    parser = argparse.ArgumentParser(description='Basic Traffic Light Simulator')
    parser.add_argument('port', help='Port for connection')
    parser.add_argument('file', help='File to send')
    args = parser.parse_args()

    # Get the file and open it (Open Sesame)
    with open(args.file, mode='r') as file_to_send:
        file_bytes = file_to_send.read()
        file_length = len(file_bytes)
        file_packet_list.append(file_bytes)
        # If the file is larger than the specified buffer size, break it down into multiple packets
        if file_length > BUFFER_SIZE:
            file_packet_list = break_down(file_bytes)

    # start serving (listening for clients)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', int(args.port)))

    # Attempt the Three-Way Handshake
    while True:
        send_seq_num = 0
        send_ack_num = 0
        send_window_size = 0
        send_checksum = 0
        send_flags = 0

        logging.info("\nServer: Waiting on a new connection on port 9001...")

        # Get SYN from Client
        recv_message, saved_client_addr = sock.recvfrom(HEADER_SIZE)
        seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)
        client_addr = saved_client_addr

        # Check if it's specifically a SYN request
        if flags == SYN:
            logging.info('Server: Received SYN from client')

            # Prepare SYN/ACK flag message, add 1 to Seq Num from client and generate Ack Num
            send_flags = SYNACK
            # Increment Ack num by 1 for checking
            send_ack_num = ack_num + 1

            # Construct message to send
            sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
            sock.sendto(sent_message, client_addr)
            logging.info('Server: Sent SYN/ACK to client with ack_num: ' + str(send_ack_num))

            # Get ACK message from Client
            recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
            while saved_client_addr != client_addr:
                recv_message, client_addr = sock.recvfrom(HEADER_SIZE)

            seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)
            if flags == ACK and seq_num - send_seq_num == 1:
                logging.info('Server: Received ACK from client with seq_num' + str(seq_num) + '\nHandshake complete!')
                logging.info('Server: Sequence num confirmed to be correct!')
                # Check if ack number was incorrect
            else:
                logging.info('Server: ACK wasn\'t received')
        else:
            logging.warning('Bad request from client.')

        # Handshake complete, connection established...

        # File transfer happens here...
        for packet in file_packet_list:
            send_checksum = calculate_checksum(send_seq_num, send_ack_num, send_window_size, send_flags, packet)
            sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
            sock.sendto(sent_message + packet.encode('utf-8'), client_addr)
            logging.info('Server: Sent the packet to client with seq_num: ' + str(send_seq_num))

            # Now, get the acknowledgement of the packet...
            recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
            while saved_client_addr != client_addr:
                recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
            seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)

            # Check received Ack Num and set new Seq Num
            check_ack_num = ack_num - send_seq_num
            send_seq_num = ack_num
            while flags != ACK or check_ack_num != len(packet):
                sock.sendto(sent_message + packet.encode('utf-8'), client_addr)
                logging.info('Server: Re-sending the lost/corrupted file to client...')

        # Terminating the connection
        send_flags = FIN
        sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
        sock.sendto(sent_message, client_addr)
        logging.info('Server: sent FIN to client')

        recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
        while saved_client_addr != client_addr:
            recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
        seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)

        if flags == ACK:
            logging.info('Server: got ACK from client in response to FIN')
            recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
            while saved_client_addr != client_addr:
                recv_message, client_addr = sock.recvfrom(HEADER_SIZE)
            seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)
            if flags == FIN:
                logging.info('Server: got FIN from client')
                send_flags = ACK
                sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
                sock.sendto(sent_message, client_addr)
                logging.info('Server: sent one last ACK to client')


# Initiate the server
server()

