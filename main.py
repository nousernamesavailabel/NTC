import socket
import threading
import csv


def receive_messages(sock):
    while True:
        try:
            message, addr = sock.recvfrom(1024)
            print(f"\n{message.decode('utf-8')}")
        except:
            break


def send_messages(sock, peer_info, local_callsign):
    while True:
        message = input()
        for peer_ip, peer_port, peer_callsign in peer_info:
            sock.sendto(f"{local_callsign}: {message}".encode('utf-8'), (peer_ip, int(peer_port)))


def start_peer(local_callsign, peer_info, local_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', local_port))

    print(f"Connected to peers. Your callsign is {local_callsign}")

    threading.Thread(target=receive_messages, args=(sock,)).start()
    threading.Thread(target=send_messages, args=(sock, peer_info, local_callsign)).start()


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

    print("Available callsigns:")
    for idx, (address, _, callsign) in enumerate(peer_info):
        print(f"{idx + 1}. {callsign} : {address}")

    local_index = int(input("Enter the number corresponding to your callsign: ")) - 1
    local_callsign, local_port = peer_info[local_index][2], int(peer_info[local_index][1])

    # Remove the local peer from the peer_info list
    peer_info = [info for info in peer_info if info[2] != local_callsign]

    start_peer(local_callsign, peer_info, local_port)
