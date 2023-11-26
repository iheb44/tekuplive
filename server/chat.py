import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )
with open("public_key.pem", "rb") as key_file:
    client_public_key = serialization.load_pem_public_key(
        key_file.read(),
    )
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))
server_socket.listen()
client_socket, client_address = server_socket.accept()

print(f"Connection established with {client_address}")

public_key_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_socket.sendall(public_key_bytes)

client_public_key_bytes = client_socket.recv(2048)
def encrypt_message(message):
    ciphertext = client_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

while True:
    server_message = input("Server: ")
    encrypted_message = encrypt_message(server_message)
    client_socket.sendall(encrypted_message)
    client_message = client_socket.recv(2048)
    decrypted_message = decrypt_message(client_message)
    print(f"Client: {decrypted_message}")

client_socket.close()
server_socket.close()
