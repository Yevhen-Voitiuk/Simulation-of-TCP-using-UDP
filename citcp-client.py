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


def sort_by_sequence_num(value):
    return value[1]


def make_message(seq_num, ack_num, window_size, checksum, flags):
    return struct.pack(MESSAGE_FORMAT, seq_num, ack_num, window_size, checksum, flags)


def client(host, port, file_name):
    # connect
    seq_num = 0
    ack_num = 0
    window_size = 0
    checksum = 0
    flags = 0

    send_seq_num = 0
    send_ack_num = 0
    send_window_size = 0
    send_checksum = 0
    send_flags = 0

    server_addr = (socket.gethostbyname(host), port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.bind((host, port))

    # exchange messages
    send_flags = SYN
    sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
    sock.sendto(sent_message, server_addr)
    logging.info('Client: Sent SYN message to server...')

    # Get a reply from server (Expect SYN/ACK)
    recv_message, server_addr = sock.recvfrom(HEADER_SIZE)
    seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)
    if flags == SYNACK and ack_num - send_ack_num == 1:
        logging.info('Client: Received SYN/ACK from server with seq_num: ' + str(seq_num))
        logging.info('Client: Ack num confirmed to be correct!')

        send_flags = ACK
        send_seq_num = seq_num + 1

        sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
        sock.sendto(sent_message, server_addr)
        logging.info('Client: sent ACK to server with seq_num: ' + str(send_seq_num))

    # File transfer happens here...
    with open(file_name, mode='w') as out_file:
        packets_to_write = []
        while True:
            recv_message, server_addr = sock.recvfrom(HEADER_SIZE + BUFFER_SIZE)
            seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message[0:HEADER_SIZE])
            if flags != FIN:
                # Get the payload without the header
                file_bytes = recv_message[HEADER_SIZE:len(recv_message)]
                file_bytes = file_bytes.decode('utf-8')
                if checksum == calculate_checksum(seq_num, ack_num, window_size, flags, file_bytes):
                    packets_to_write.append((file_bytes, seq_num))
                else:
                    print("EPIC Problem happened, checksum didn\'t match")

                send_flags = ACK
                send_ack_num = seq_num + len(file_bytes)

                sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
                sock.sendto(sent_message, server_addr)
                logging.info('Client: sent ACK for received packet... ack_num: ' + str(send_ack_num))
            else:
                # Got FIN from server, meaning we have all packets. Get them in order and write out to a file
                packets_to_write.sort(key=sort_by_sequence_num)
                for packet in packets_to_write:
                    out_file.write(packet[0])
                break

    # Terminating the connection...
    logging.info("Client: Received FIN message from server")

    # Server sends ACK back to the FIN
    send_flags = ACK
    send_ack_num = seq_num + 1
    sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
    sock.sendto(sent_message, server_addr)
    logging.info('Client: Sent ACK to server in response to FIN')

    # Now, server sends its FIN to client...
    send_flags = FIN
    sent_message = make_message(send_seq_num, send_ack_num, send_window_size, send_checksum, send_flags)
    sock.sendto(sent_message, server_addr)
    logging.info('Client: Sent FIN to server')

    # Waiting on server's ACK...
    recv_message, server_addr = sock.recvfrom(HEADER_SIZE)
    seq_num, ack_num, window_size, checksum, flags = struct.unpack(MESSAGE_FORMAT, recv_message)
    if flags == ACK:
        logging.info('Client: Received ACK from server in response to FIN, we\'re done!')
        sock.close()
    else:
        logging.info('Client: ACK from server wasn\'t received, something went wrong...')
        sock.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Basic Traffic Light Simulator')
    parser.add_argument('host', help='IP address of the server.')
    parser.add_argument('port', type=int, help='Port that is used for connection')
    parser.add_argument('file_name',
                        help='Name of the file to be transmitted')
    args = parser.parse_args()
    client(args.host, args.port, args.file_name)


