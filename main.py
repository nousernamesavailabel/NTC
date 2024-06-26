import socket
import threading
import csv
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog
import time
import os

selected_file_path = ""
tftp_on = False
stop_event = threading.Event()
first_ack = True

version = "1.0.0"


def tftp_server(sock, stop_event, display_area, storage_directory="tftp_storage", block_size=512):
    global first_ack
    if not os.path.exists(storage_directory):
        os.makedirs(storage_directory)

    sock.settimeout(1.0)  # Set a timeout for the socket operations

    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(block_size + 4)  # TFTP packets are block_size of data + 4 bytes header
            if not data:
                continue

            opcode = data[:2]
            parts = data[2:].split(b'\x00')
            if len(parts) < 2:
                display_area.config(state=tk.NORMAL)
                display_area.insert(tk.END, f"Malformed WRQ packet from {addr}\n")
                display_area.yview(tk.END)
                display_area.config(state=tk.DISABLED)
                continue
            filename = parts[0].decode('ascii')
            mode = parts[1].decode('ascii')

            display_area.config(state=tk.NORMAL)
            display_area.insert(tk.END, f"Received WRQ: filename={filename}, mode={mode}, from={addr}\n")
            display_area.yview(tk.END)
            display_area.config(state=tk.DISABLED)

            if opcode == b'\x00\x02':  # Write request (WRQ)
                filepath = os.path.join(storage_directory, filename)
                with open(filepath, 'wb') as file:
                    block_number = 0
                    while True:
                        ack = b'\x00\x04' + block_number.to_bytes(2, 'big')
                        sock.sendto(ack, addr)
                        if first_ack:
                            first_ack=False
                        else:
                            first_ack=True
                        display_area.config(state=tk.NORMAL)
                        if first_ack:
                            display_area.insert(tk.END, f"Sent ACK for block {block_number} to {addr}\n")
                            display_area.yview(tk.END)
                            display_area.config(state=tk.DISABLED)
                            status_bar.config(text=f"Sent ACK for block {block_number} to {addr}")

                        try:
                            data, addr = sock.recvfrom(block_size + 4)
                        except socket.timeout:
                            if stop_event.is_set():
                                break
                            continue

                        if not data:
                            break

                        opcode = data[:2]
                        recv_block_number = int.from_bytes(data[2:4], 'big')
                        block_data = data[4:]

                        display_area.config(state=tk.NORMAL)
                        #display_area.insert(tk.END, f"Received packet: opcode={opcode}, block_number={recv_block_number}, from={addr}\n")
                        #display_area.insert(tk.END, f"Received Packet: block number={block_number}, from={addr}\n")
                        display_area.yview(tk.END)
                        display_area.config(state=tk.DISABLED)

                        if opcode == b'\x00\x03' and recv_block_number == block_number + 1:
                            file.write(block_data)
                            block_number += 1
                            display_area.config(state=tk.NORMAL)
                            display_area.insert(tk.END, f"Received block {block_number} of {filename} from {addr}\n")
                            display_area.yview(tk.END)
                            display_area.config(state=tk.DISABLED)
                            status_bar.config(text=f"Received block {block_number} of {filename} from {addr}")

                            if len(block_data) < block_size:
                                display_area.config(state=tk.NORMAL)
                                display_area.insert(tk.END, f"File transfer complete for {filename}\n")
                                display_area.yview(tk.END)
                                display_area.config(state=tk.DISABLED)
                                status_bar.config(text=f"File transfer complete for {filename}")
                                # Send final ACK
                                ack = b'\x00\x04' + block_number.to_bytes(2, 'big')
                                sock.sendto(ack, addr)
                                display_area.config(state=tk.NORMAL)
                                display_area.insert(tk.END, f"Sent final ACK for block {block_number} to {addr}\n")
                                first_ack = True
                                display_area.yview(tk.END)
                                display_area.config(state=tk.DISABLED)
                                status_bar.config(text=f"Sent final ACK for block {block_number} to {addr} // TFTP Status: Ready")
                                break
        except socket.timeout:
            continue
        except Exception as e:
            display_area.config(state=tk.NORMAL)
            display_area.insert(tk.END, f"Error in TFTP server: {e}\n")
            display_area.yview(tk.END)
            display_area.config(state=tk.DISABLED)
            status_bar.config(text=f"Error in TFTP server: {e}")

    #display_area.config(state=tk.NORMAL)
    #display_area.insert(tk.END, "TFTP server stopping.\n")
    #display_area.yview(tk.END)
    #display_area.config(state=tk.DISABLED)
    status_bar.config(text="TFTP server stopped.")
    sock.close()




def tftp_client(sock, filename, server_address, display_area, block_size):
    global status_bar
    try:
        wrq = b'\x00\x02' + os.path.basename(filename).encode('ascii') + b'\x00octet\x00'
        sock.sendto(wrq, server_address)
        display_area.config(state=tk.NORMAL)
        display_area.insert(tk.END, f"Sent WRQ for {filename} to {server_address}\n")
        display_area.yview(tk.END)
        display_area.config(state=tk.DISABLED)

        with open(filename, 'rb') as file:
            total_size = 0
            block_number = 0
            while True:
                block = file.read(block_size)
                if not block:
                    break
                total_size += len(block)
                status_bar.config(text=f"Sent {total_size} bytes")
                block_number += 1
                packet = b'\x00\x03' + block_number.to_bytes(2, 'big') + block
                sock.sendto(packet, server_address)
                display_area.config(state=tk.NORMAL)
                display_area.insert(tk.END, f"Sent block {block_number} of {filename} to {server_address}\n")
                display_area.yview(tk.END)
                display_area.config(state=tk.DISABLED)
                status_bar.config(text=f"Sent block {block_number} of {filename} to {server_address}")

                while True:
                    ack, _ = sock.recvfrom(4)
                    if ack[:2] == b'\x00\x04' and int.from_bytes(ack[2:], 'big') == block_number:
                        display_area.config(state=tk.NORMAL)
                        display_area.insert(tk.END, f"Received ACK for block {block_number}\n")
                        display_area.yview(tk.END)
                        display_area.config(state=tk.DISABLED)
                        status_bar.config(text=f"Received ACK for block {block_number}")
                        break
                    else:
                        display_area.config(state=tk.NORMAL)
                        display_area.insert(tk.END, f"Incorrect ACK received, retransmitting block {block_number}\n")
                        display_area.yview(tk.END)
                        display_area.config(state=tk.DISABLED)
                        sock.sendto(packet, server_address)
                        status_bar.config(text=f"Incorrect ACK received, retransmitting block {block_number}")

            # If the last block is less than the block size, it indicates the end of the file.
            if len(block) == block_size:
                block_number += 1
                packet = b'\x00\x03' + block_number.to_bytes(2, 'big') + b''
                sock.sendto(packet, server_address)
                display_area.config(state=tk.NORMAL)
                display_area.insert(tk.END, f"Sent final block {block_number} of {filename} to {server_address}\n")
                display_area.yview(tk.END)
                display_area.config(state=tk.DISABLED)

                while True:
                    ack, _ = sock.recvfrom(4)
                    if ack[:2] == b'\x00\x04' and int.from_bytes(ack[2:], 'big') == block_number:
                        display_area.config(state=tk.NORMAL)
                        display_area.insert(tk.END, f"Received final ACK for block {block_number}\n")
                        display_area.yview(tk.END)
                        display_area.config(state=tk.DISABLED)
                        break

            status_bar.config(text="File transfer complete")
            display_area.config(state=tk.NORMAL)
            display_area.insert(tk.END, f"File transfer complete for {filename}\n")
            display_area.yview(tk.END)
            display_area.config(state=tk.DISABLED)
            status_bar.config(text=f"File transfer complete for {filename}")
    except Exception as e:
        display_area.config(state=tk.NORMAL)
        display_area.insert(tk.END, f"Error in TFTP client: {e}\n")
        display_area.yview(tk.END)
        display_area.config(state=tk.DISABLED)


def select_file():
    global selected_file_path
    selected_file_path = filedialog.askopenfilename()
    status_bar.config(text=f"Selected file: {selected_file_path}")
    print(f"Selected file: {selected_file_path}")
    return selected_file_path

def receive_messages(sock, display_area, ack_received_event, stop_event):
    while not stop_event.is_set():
        try:
            message, addr = sock.recvfrom(1024)
            decoded_message = message.decode('utf-8')

            if decoded_message.startswith("ACK:"):
                # Handle the ACK message
                ack_received_event.set()
            else:
                display_area.config(state=tk.NORMAL)
                display_area.insert(tk.END, f"{decoded_message}\n")
                display_area.yview(tk.END)
                display_area.config(state=tk.DISABLED)
                # Send back an ACK to the sender with the first four characters of the message
                ack_message = f"ACK:{decoded_message[:4]}"
                sock.sendto(ack_message.encode('utf-8'), addr)
        except socket.error:
            break

def send_messages(sock, peer_ip, peer_port, local_callsign, message_entry, display_area, ack_received_event, send_button, ack_timeout, recipient_callsign):
    message = message_entry.get()
    if message:
        msg_with_callsign = f"{local_callsign}: {message}"
        sock.sendto(msg_with_callsign.encode('utf-8'), (peer_ip, peer_port))

        # Insert the message immediately with recipient callsign
        display_area.config(state=tk.NORMAL)
        start_index = display_area.index(tk.END)
        display_area.insert(tk.END, f"You to {recipient_callsign}: {message}\n", "pending_ack")
        display_area.yview(tk.END)
        display_area.config(state=tk.DISABLED)

        # Disable send button
        send_button.config(state=tk.DISABLED)

        # Wait for ACK
        ack_received_event.clear()
        start_time = time.time()

        while not ack_received_event.is_set():
            if time.time() - start_time > ack_timeout:
                display_area.config(state=tk.NORMAL)
                display_area.insert(f"{start_index} lineend", " -no ack\n")
                display_area.tag_remove("pending_ack", start_index, tk.END)
                display_area.yview(tk.END)
                display_area.config(state=tk.DISABLED)
                break
            time.sleep(0.1)

        if ack_received_event.is_set():
            display_area.config(state=tk.NORMAL)
            display_area.insert(f"{start_index} lineend", " -ack\n")
            display_area.tag_remove("pending_ack", start_index, tk.END)
            display_area.yview(tk.END)
            display_area.config(state=tk.DISABLED)

        # Re-enable send button
        send_button.config(state=tk.NORMAL)

        message_entry.delete(0, tk.END)

def start_peer(sock, local_callsign, peer_info, display_area, message_entry, peer_dropdown, send_button, ack_timeout, stop_event):
    ack_received_event = threading.Event()

    threading.Thread(target=receive_messages, args=(sock, display_area, ack_received_event, stop_event)).start()

    def send_button_command(event=None):
        recipient_info = peer_info[peer_dropdown.current()]
        recipient_callsign = recipient_info[2]
        send_messages(
            sock,
            recipient_info[0],
            int(recipient_info[1]),
            local_callsign,
            message_entry,
            display_area,
            ack_received_event,
            send_button,
            ack_timeout,
            recipient_callsign
        )

    send_button.config(command=send_button_command)
    message_entry.bind('<Return>', send_button_command)


def send_file():
    if selected_file_path:
        server_ip = peer_info[peer_dropdown.current()][0]
        server_port = 69
        block_size = int(block_size_dropdown.get())
        status_bar.config(text="Starting file transfer...")
        print(f"Starting file transfer to {server_ip}:{server_port} with block size {block_size}")
        threading.Thread(target=tftp_client, args=(sock, selected_file_path, (server_ip, server_port), display_area, block_size)).start()

def on_save(local_callsign_var, local_port_entry, ack_timeout_entry, peer_info, display_area, message_entry, peer_dropdown, save_button, callsign_dropdown, send_button, stop_event):
    global sock
    selected_value = local_callsign_var.get()
    local_callsign = selected_value.split(' ')[0]  # Get only the callsign part

    local_port = int(local_port_entry.get())
    ack_timeout = int(ack_timeout_entry.get())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', local_port))

    display_area.config(state=tk.NORMAL)
    display_area.insert(tk.END, f"Chat online. Your callsign is {local_callsign}\n")
    display_area.config(state=tk.DISABLED)

    save_button.config(state=tk.DISABLED)
    callsign_dropdown.config(state=tk.DISABLED)
    local_port_entry.config(state=tk.DISABLED)
    ack_timeout_entry.config(state=tk.DISABLED)

    # Remove the local peer from the peer_info list
    peer_info = [info for info in peer_info if info[2] != local_callsign]

    # Update the peer dropdown
    peer_dropdown['values'] = [f"{callsign} ({address}:{port})" for address, port, callsign in peer_info]
    peer_dropdown.current(0)

    start_peer(sock, local_callsign, peer_info, display_area, message_entry, peer_dropdown, send_button, ack_timeout, stop_event)

    # Start the TFTP server with the selected block size
    #block_size = int(block_size_dropdown.get())
    #tftp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #tftp_sock.bind(('0.0.0.0', 69))
    #threading.Thread(target=tftp_server, args=(tftp_sock, stop_event, display_area, "tftp_storage", block_size)).start()

    # Ensure sock is passed to on_closing
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root, sock, stop_event))


def start_stop_tftp_server():
    global tftp_sock, tftp_server_thread, stop_event, tftp_on
    if not tftp_on:
        block_size = int(block_size_dropdown.get())
        tftp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tftp_sock.bind(('0.0.0.0', 69))
        stop_event.clear()
        tftp_server_thread = threading.Thread(target=tftp_server, args=(tftp_sock, stop_event, display_area, "tftp_storage", block_size))
        tftp_server_thread.start()
        status_bar.config(text=f"Status: TFTP Server Running // Block Size = {block_size}")
        block_size_dropdown.config(state=tk.DISABLED)
        start_tftp_server_button.config(text="Stop TFTP Server")
        tftp_on = True
    else:
        stop_event.set()
        tftp_server_thread.join(1)  # Non-blocking join
        tftp_sock.close()
        status_bar.config(text="Status: TFTP Server Stopped")
        start_tftp_server_button.config(text="Start TFTP Server")
        block_size_dropdown.config(state=tk.NORMAL)
        tftp_on = False



def read_addresses(file_name):
    peer_info = []

    with open(file_name, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            address = row['address']
            port = row['port']
            callsign = row['callsign']
            peer_info.append((address, port, callsign))

    return peer_info

def on_closing(root, sock, stop_event):
    stop_event.set()
    sock.close()
    root.destroy()

if __name__ == "__main__":
    peer_info = read_addresses('addresses.csv')

    root = tk.Tk()
    root.title("Peer-to-Peer Chat")

    top_frame = tk.Frame(root)
    top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

    my_station_label = tk.Label(top_frame, text="My Station:")
    my_station_label.grid(row=0, column=0, padx=10, pady=10)

    local_callsign_var = tk.StringVar()
    callsign_dropdown = ttk.Combobox(top_frame, textvariable=local_callsign_var, state="readonly")
    callsign_dropdown['values'] = [f"{callsign} ({address})" for address, _, callsign in peer_info]
    callsign_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    local_port_label = tk.Label(top_frame, text="Local Port:")
    local_port_label.grid(row=0, column=2, padx=10, pady=10)

    local_port_entry = tk.Entry(top_frame)
    local_port_entry.insert(0, "1234")
    local_port_entry.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

    ack_timeout_label = tk.Label(top_frame, text="ACK Timeout (s):")
    ack_timeout_label.grid(row=0, column=4, padx=10, pady=10)

    ack_timeout_entry = tk.Entry(top_frame)
    ack_timeout_entry.insert(0, "5")
    ack_timeout_entry.grid(row=0, column=5, padx=5, pady=5, sticky="ew")

    stop_event = threading.Event()

    save_button = tk.Button(top_frame, text="Save", command=lambda: on_save(
        local_callsign_var,
        local_port_entry,
        ack_timeout_entry,
        peer_info,
        display_area,
        message_entry,
        peer_dropdown,
        save_button,
        callsign_dropdown,
        send_button,
        stop_event
    ))
    save_button.grid(row=0, column=6, padx=5, pady=5, sticky="ew")

    display_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED)
    display_area.grid(row=1, column=0, padx=10, pady=10, columnspan=7, sticky="nsew")

    frame = tk.Frame(root)
    frame.grid(row=2, column=0, padx=10, pady=10, columnspan=7, sticky="ew")

    message_entry = tk.Entry(frame)
    message_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew", columnspan=5)

    peer_dropdown = ttk.Combobox(frame, state="readonly", width=25)
    peer_dropdown['values'] = [f"{callsign} ({address}:{port})" for address, port, callsign in peer_info]
    peer_dropdown.current(0)
    peer_dropdown.grid(row=0, column=6, padx=5, pady=5, sticky="ew")

    send_button = tk.Button(frame, text="Send", command=None)
    send_button.grid(row=0, column=7, padx=5, pady=5, sticky="ew")

    select_file_button = tk.Button(frame, text="Select File", command=select_file)
    select_file_button.grid(row=1, column=3, padx=5, pady=5, sticky="ew")

    send_file_button = tk.Button(frame, text="Send File", command=send_file)
    send_file_button.grid(row=1, column=4, padx=5, pady=5, sticky="ew")

    block_size_label = tk.Label(frame, text="Block Size:")
    block_size_label.grid(row=1, column=0, padx=10, pady=10)

    block_size_dropdown = ttk.Combobox(frame, state="readonly", values=[16, 32, 64, 128, 256, 512, 1024, 2048, 4096])
    block_size_dropdown.current(5)
    block_size_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

    start_tftp_server_button = tk.Button(frame, text="Start TFTP Server", command=start_stop_tftp_server)
    start_tftp_server_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")

    status_bar = tk.Label(root, text="Status: TFTP Server Not Started", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_bar.grid(row=3, column=0, columnspan=7, padx=5, pady=5, sticky="ew")

    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    root.mainloop()
