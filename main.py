import socket
import threading
import csv
import tkinter as tk
from tkinter import scrolledtext, ttk
import time

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

def on_save(local_callsign_var, local_port_entry, ack_timeout_entry, peer_info, display_area, message_entry, peer_dropdown, save_button, callsign_dropdown, send_button, stop_event):
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

    # Ensure sock is passed to on_closing
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root, sock, stop_event))

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

    message_entry = tk.Entry(frame, width=50)
    message_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

    peer_dropdown = ttk.Combobox(frame, state="readonly", width=25)
    peer_dropdown['values'] = [f"{callsign} ({address}:{port})" for address, port, callsign in peer_info]
    peer_dropdown.current(0)
    peer_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    send_button = tk.Button(frame, text="Send", command=None)
    send_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    root.mainloop()
