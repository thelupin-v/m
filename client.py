#!/usr/bin/env python3
import socket
import threading
import json
import logging
from px import DiffieHellman, HMAC  # Assuming your custom protocol file is named px.py
import hashlib

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Client")


class Client:
    def __init__(self, server_host="127.0.0.1", server_port=65432):
        self.server_host = server_host
        self.server_port = server_port
        self.dh = DiffieHellman()
        self.dh.generate_parameters()
        self.dh.generate_keypair()
        self.shared_secret = None
        self.derived_key = None
        self.running = True  # Flag to control the thread loop

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect((self.server_host, self.server_port))
                logger.info("Connected to server")
                listen_thread = threading.Thread(target=self.listen_to_server, args=(client_socket,))
                listen_thread.start()

                self.send_key_exchange(client_socket)

                # Wait for the listener thread to finish before exiting
                listen_thread.join()
            except Exception as e:
                logger.error(f"Error in client: {e}")
            finally:
                logger.info("Client shutting down")
                self.running = False

    def listen_to_server(self, client_socket):
        while self.running:
            try:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    logger.warning("Server closed the connection")
                    break

                message = json.loads(data)
                if message["type"] == "key_exchange_request":
                    self.handle_key_exchange(message)

            except OSError as e:
                logger.error(f"Socket error: {e}")
                break
            except Exception as e:
                logger.error(f"Error listening to server: {e}")
                break

    def send_key_exchange(self, client_socket):
        recipient_id = input("Enter recipient client ID: ")
        message = {
            "type": "key_exchange_request",
            "recipient_id": int(recipient_id),
            "sender_public_key": self.dh.export_public_key()
        }
        try:
            client_socket.sendall(json.dumps(message).encode('utf-8'))
            logger.info(f"Sent key exchange request to client {recipient_id}")
        except Exception as e:
            logger.error(f"Error sending key exchange request: {e}")

    def handle_key_exchange(self, message):
        try:
            sender_public_key = int(message["sender_public_key"], 16)
            self.shared_secret = self.dh.compute_shared_secret(sender_public_key)
            logger.info(f"Shared secret established: {self.shared_secret.hex()}")
            print(f"Shared secret (local): {self.shared_secret.hex()}")

            # Derive a key from the shared secret using HKDF
            self.derived_key = self.hkdf_derive_key(self.shared_secret, b"hkdf-salt", 32)
            logger.info(f"Derived key: {self.derived_key.hex()}")
            print(f"Derived key: {self.derived_key.hex()}")

            # Notify the peer that the shared secret and derived key are established
            print("Both users have now established the shared secret and derived key.")
        except Exception as e:
            logger.error(f"Error handling key exchange: {e}")

    def hkdf_derive_key(self, shared_secret, salt, length=32):
        """Derive a key from the shared secret using HKDF."""
        # Use HMAC-SHA256 for HKDF
        prk = HMAC(salt, hashlib.sha256).compute(shared_secret)
        okm = b""
        previous_block = b""
        block_index = 1

        # Generate enough blocks to satisfy the required length
        while len(okm) < length:
            data = previous_block + b"" + bytes([block_index])
            previous_block = HMAC(prk, hashlib.sha256).compute(data)
            okm += previous_block
            block_index += 1

        return okm[:length]


if __name__ == "__main__":
    client = Client()
    client.start()
