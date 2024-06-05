import socket
import threading
import csv
import tkinter as tk
from tkinter import scrolledtext, ttk
import time

# Timeout duration for waiting for ACK in seconds
ACK_TIMEOUT = 2

def receive_messages(sock, display_area, ack_received_event):
    while True:
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
                # Send back an ACK to the sender
                ack_message = f"ACK:{decoded_message}"
                sock.sendto(ack_message.encode('utf-8'), addr)
        except:
            break

def send_messages(sock, peer_ip, peer_port, local_callsign, message_entry, display_area, ack_received_event):
    message = message_entry.get()
    if message:
        msg_with_callsign = f"{local_callsign}: {message}"
        sock.sendto(msg_with_callsign.encode('utf-8'), (peer_ip, peer_port))

        # Wait for ACK
        ack_received_event.clear()
        start_time = time.time()

        while not ack_received_event.is_set():
            if time.time() - start_time > ACK_TIMEOUT:
                display_area.config(state=tk.NORMAL)
                display_area.insert(tk.END, "No ACK received, message might be lost.\n")
                display_area.yview(tk.END)
                display_area.config(state=tk.DISABLED)
                break
            time.sleep(0.1)

        if ack_received_event.is_set():
            display_area.config(state=tk.NORMAL)
            display_area.insert(tk.END, f"You: {message}\n")
            display_area.yview(tk.END)
            display_area.config(state=tk.DISABLED)

        message_entry.delete(0, tk.END)

def start_peer(sock, local_callsign, peer_info, display_area, message_entry, peer_dropdown):
    ack_received_event = threading.Event()

    threading.Thread(target=receive_messages, args=(sock, display_area, ack_received_event)).start()

    def send_button_command(event=None):
        send_messages(
            sock,
            peer_info[peer_dropdown.current()][0],
            int(peer_info[peer_dropdown.current()][1]),
            local_callsign,
            message_entry,
            display_area,
            ack_received_event
        )

    send_button = tk.Button(root, text="Send", command=send_button_command)
    send_button.grid(row=3, column=2, padx=5, pady=5, sticky="ew")

    message_entry.bind('<Return>', send_button_command)

def on_save(local_callsign_var, peer_info, display_area, message_entry, peer_dropdown, save_button, callsign_dropdown):
    selected_value = local_callsign_var.get()
    local_callsign = selected_value.split(' ')[0]  # Get only the callsign part

    local_port = int([port for addr, port, cs in peer_info if cs == local_callsign][0])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', local_port))

    display_area.config(state=tk.NORMAL)
    display_area.insert(tk.END, f"Chat online. Your callsign is {local_callsign}\n")
    display_area.config(state=tk.DISABLED)

    save_button.config(state=tk.DISABLED)
    callsign_dropdown.config(state=tk.DISABLED)

    # Remove the local peer from the peer_info list
    peer_info = [info for info in peer_info if info[2] != local_callsign]

    # Update the peer dropdown
    peer_dropdown['values'] = [f"{callsign} ({address}:{port})" for address, port, callsign in peer_info]
    peer_dropdown.current(0)

    start_peer(sock, local_callsign, peer_info, display_area, message_entry, peer_dropdown)

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

    save_button = tk.Button(top_frame, text="Save", command=lambda: on_save(
        local_callsign_var,
        peer_info,
        display_area,
        message_entry,
        peer_dropdown,
        save_button,
        callsign_dropdown
    ))
    save_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

    display_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED)
    display_area.grid(row=1, column=0, padx=10, pady=10, columnspan=3, sticky="nsew")

    frame = tk.Frame(root)
    frame.grid(row=2, column=0, padx=10, pady=10, columnspan=3, sticky="ew")

    message_entry = tk.Entry(frame, width=50)
    message_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

    peer_dropdown = ttk.Combobox(frame, state="readonly", width=25)
    peer_dropdown['values'] = [f"{callsign} ({address}:{port})" for address, port, callsign in peer_info]
    peer_dropdown.current(0)
    peer_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    root.mainloop()
