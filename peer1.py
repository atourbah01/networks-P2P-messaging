import sys

import socket

import select

import time

import PySimpleGUI as sg  # for the GUI

import os

import subprocess

CRC32_TABLE = [

    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,

    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,

    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,

    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,

    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,

    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,

    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,

    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,

    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,

    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,

    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,

    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,

    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,

    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,

    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,

    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,

    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,

    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,

    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,

    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,

    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,

    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,

    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,

    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,

    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,

    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,

    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,

    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,

    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,

    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,

    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,

    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,

    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,

    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,

    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,

    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,

    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,

    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,

    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,

    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,

    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,

    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,

    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d ]

RETRANSMISSION_TIMEOUT = 2

MAX_RETRANSMISSIONS = 6

RETRANSMISSION_LIMIT = 60  # 1 min

BUFFER_SIZE = 10000

HOST = '127.0.0.1'

FILE_PORT = 1234

received_files=[]

def open_file(file_path):
    """
    Opens a file given a file path.
    Args:
    file_path (str): The path to the file to open.
    Returns:
    None
    """


    if os.path.exists(file_path):
         os.startfile(file_path)
    else:
         print(f"Error: File not found at {file_path}")


def crc32(data):
    crc = 0xffffffff

    for byte in data:
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ byte) & 0xff]

    return crc ^ 0xffffffff


def send_message(message, sequence_nb, retransmissions=0):
    if message.lower() == 'exit':
        sock.sendto(message.encode(), peer_address)

        sock.close()

        sys.exit()

    crc32_value = crc32(message.encode())

    message = f"{sequence_nb}: {crc32_value}: {message}"

    sock.sendto(message.encode(), peer_address)

    unacknowledged_messages[sequence_nb] = (message, time.time(), retransmissions)

    if retransmissions > 0:
        print(f"Retransmitting message {sequence_nb} (retransmission {retransmissions}): {message}")

    return sequence_nb + 1


def receive_message(sock):
    received_message, _ = sock.recvfrom(2048)

    decoded_message = received_message.decode()

    if decoded_message.lower() == 'exit':

        print("Peer 2 has left by typing or pressing 'exit'")

        sock.close()

        sys.exit()

    elif decoded_message.startswith("ACK:"):

        ack_sequence_nb = int(decoded_message.split(" ")[1])

        unacknowledged_messages.pop(ack_sequence_nb, None)

        print(f"Received ACK for message {ack_sequence_nb}")

    else:

        message_sequence_nb, crc32_received, message_text = decoded_message.split(": ", 2)

        message_sequence_nb = int(message_sequence_nb)

        crc32_received = int(crc32_received)

        if crc32(message_text.encode()) == crc32_received:

            if message_sequence_nb not in received_messages:
                received_messages[message_sequence_nb] = message_text

                print(f"Received message from Peer 2: {message_text}")
                if message_text in received_files:
                    values['-EMPTY-'].update(value=message_text)

            received_files.append(message_text)
            ack_message = f"ACK: {message_sequence_nb}"

            sock.sendto(ack_message.encode(), peer_address)


        else:

            print("CRC32 mismatch, discarding message")


def send_file(file_path):
    # Send a file to the other peer

    with open(file_path, 'rb') as file:
        data = file.read()

    # Send the file in packets

    packet_size = 1024

    packets = [data[i:i + packet_size] for i in range(0, len(data), packet_size)]

    num_packets = len(packets)

    send_message(f"START {num_packets} {file_path}", 0)

    for i, packet in enumerate(packets, start=1):
        sequence_nb = send_message(packet, i)

        time.sleep(0.001)  # wait a little between packets to not overwhelm the network

    send_message("END", num_packets + 1)


def receive_file(files_message, file_path):
    # Receive a file from the other peer

    file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    file_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    file_sock.bind((HOST, FILE_PORT))

    file_sock.listen(1)

    print('Waiting for incoming file...')

    conn, addr = file_sock.accept()

    print('File incoming from: ', addr)

    # Receive file name

    file_name = conn.recv(BUFFER_SIZE).decode()

    print('File name: ', file_name)

    # Receive file size

    file_size = int(conn.recv(BUFFER_SIZE).decode())

    print('File size: ', file_size)

    # Receive file data

    file_data = b''

    while len(file_data) < file_size:
        data = conn.recv(BUFFER_SIZE)

        file_data += data

    # Save file to disk


    with open(file_path,'wb') as f:
            f.write(file_data)

    print('File saved: ', file_path)
    subprocess.call('xdg-open',file_path)


    conn.close()

    file_sock.close()
    received_files.append(file_path)
def receive_file_gui():
    file_path=sg.popup_get_file('Select file to open', save_as=True)
    message=receive_message(sock)
    if file_path in message:
        receive_file(message,file_path)
        if file_path not in receive_file(message,file_path):
            receive_file(message,file_path).append(file_path)
            sg.popup(f"File Saved: {file_path}")

server_address = ('127.0.0.1', 12001)

peer_address = ('127.0.0.1', 12000)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(server_address)

sock.setblocking(0)

print("Peer 1 ready to send and receive messages")

sequence_nb = 1

unacknowledged_messages = {}

received_messages = {}

last_retransmission_check = time.time()

# GUI


sg.theme('DarkTeal2')

layout = [[sg.Multiline(size=(100, 30), key='-OUTPUT-', autoscroll=True, disabled=True, reroute_stdout=True,
                        text_color='white')],

          [sg.Input(key='-INPUT-', size=(90, 2))],

          [sg.Button('Send', button_color=('white', 'darkgreen'), border_width=5, pad=(10, 10)),

           [sg.Text("Select a file to send:")],

           [sg.Input(key="file_path"), sg.FileBrowse()],

           [sg.Button("Send File")],

           sg.Button('Receive File', button_color=('white', 'blue'), border_width=5, pad=(10, 10)),

           sg.Button('Exit', button_color=('white', 'darkred'), border_width=5, pad=(10, 10))]]

window = sg.Window('Peer 1', layout, finalize=True)


def retransmit_dropped_packet(sequence_nb, message, retransmissions):
    return send_message(message, sequence_nb, retransmissions + 1)


while True:

    event, values = window.read(timeout=100)

    if event in (sg.WIN_CLOSED, 'Exit'):

        sock.sendto("exit".encode(), peer_address)

        sock.close()

        break


    elif event == '-UPLOAD-':

        file_path = values['-FILE-']

        if file_path:
            send_file(file_path)


    elif event == "Send File":

        # get file path from input field

        file_path = values["file_path"]

        # check if file exists

        if not os.path.exists(file_path):

            sg.popup_error("File not found!")

        else:

            # send file
            send_file(file_path)

    elif event == 'Receive File':

        file_path= values["file_path"]
        receive_file_gui()


    elif event == 'Send':

        message = values['-INPUT-']

        crc32_value = crc32(message.encode())

        sequence_nb = send_message(message, sequence_nb, 0)

        window['-INPUT-'].update('')

        window['-OUTPUT-'].update('', append=True, text_color_for_value='white', font=("Helvetica", 10, "bold"))

    ready_to_read, _, _ = select.select([sock], [], [], 0)

    for s in ready_to_read:

        if s == sock:

            received_msg = receive_message(sock)

            if received_msg:
                print(received_msg)


    current_time = time.time()

    if current_time - last_retransmission_check > RETRANSMISSION_TIMEOUT:

        for seq_nb, (message, timestamp, retransmissions) in list(unacknowledged_messages.items()):

            if current_time - timestamp > RETRANSMISSION_TIMEOUT:

                if retransmissions < MAX_RETRANSMISSIONS:

                    unacknowledged_messages.pop(seq_nb, None)

                    retransmit_dropped_packet(seq_nb, message.split(': ', 2)[-1], retransmissions)

                else:

                    print(f"Message {seq_nb} dropped after reaching maximum retransmissions")

                    unacknowledged_messages.pop(seq_nb, None)

        last_retransmission_check = current_time

    # formatting the GUI

    window['-OUTPUT-'].Widget.configure(highlightthickness=2, highlightbackground='coral')

    window['-INPUT-'].Widget.configure(highlightthickness=2, highlightbackground='coral')

    window['-OUTPUT-'].set_vscroll_position(1)

    # italicizing and coloring ACKs and errors

    output_widget = window['-OUTPUT-'].Widget

    output_widget.tag_configure("ACK", foreground="blue", font=("Helvetica", 10, "italic"))

    output_widget.tag_configure("error", foreground="red", font=("Helvetica", 10, "italic"))

    lines = output_widget.get("1.0", "end-1c").split("\n")

    for i, line in enumerate(lines):

        if "Received ACK" in line:

            output_widget.tag_add("ACK", f"{i + 1}.0", f"{i + 1}.end")

        elif "CRC32 mismatch" in line:

            output_widget.tag_add("error", f"{i + 1}.0", f"{i + 1}.end")

            window.close()
sock.close()
