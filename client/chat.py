import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))

while True:
    # Client sends a message
    client_message = input("Client: ")
    client_socket.sendall(client_message.encode())

    # Client receives a message
    server_message = client_socket.recv(2048)
    print(f"Server: {server_message}")

client_socket.close()


