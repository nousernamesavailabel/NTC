import socket
import threading

def receive_messages(sock):
    while True:
        try:
            message, addr = sock.recvfrom(1024)
            print(f"\nFriend: {message.decode('utf-8')}")
        except:
            break

def send_messages(sock, peer_ip, peer_port):
    while True:
        message = input()
        sock.sendto(message.encode('utf-8'), (peer_ip, peer_port))

def start_peer(peer_ip, peer_port=12345, local_port=12345):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', local_port))

    print(f"Connected to {peer_ip}:{peer_port}")

    threading.Thread(target=receive_messages, args=(sock,)).start()
    threading.Thread(target=send_messages, args=(sock, peer_ip, peer_port)).start()

if __name__ == "__main__":
    peer_ip = input("Enter the IP address of the peer: ").strip()
    peer_port = int(input("Enter the port number of the peer: ").strip())
    local_port = int(input("Enter your local port number: ").strip())

    start_peer(peer_ip, peer_port, local_port)
