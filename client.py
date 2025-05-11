#!/usr/bin/env python3
import socket
import threading
import json
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Server")

class Server:
    def __init__(self, host="127.0.0.1", port=65432):
        self.host = host
        self.port = port
        self.clients = {}  # Store connected clients {client_id: connection}
        self.lock = threading.Lock()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            logger.info(f"Server started on {self.host}:{self.port}")

            while True:
                conn, addr = server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        client_id = addr[1]  # Use port as a unique ID for simplicity
        with self.lock:
            self.clients[client_id] = conn
        logger.info(f"Client {client_id} connected from {addr}")

        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break

                message = json.loads(data)
                if message["type"] == "key_exchange_request":
                    self.forward_key_exchange(client_id, message)

        except Exception as e:
            logger.error(f"Error with client {client_id}: {e}")
        finally:
            with self.lock:
                del self.clients[client_id]
            conn.close()
            logger.info(f"Client {client_id} disconnected")

    def forward_key_exchange(self, sender_id, message):
        recipient_id = message["recipient_id"]
        with self.lock:
            if recipient_id in self.clients:
                recipient_conn = self.clients[recipient_id]
                recipient_conn.sendall(json.dumps(message).encode('utf-8'))
                logger.info(f"Forwarded key exchange request from {sender_id} to {recipient_id}")
            else:
                sender_conn = self.clients[sender_id]
                error_msg = {"type": "error", "message": "Recipient not connected"}
                sender_conn.sendall(json.dumps(error_msg).encode('utf-8'))
                logger.warning(f"Recipient {recipient_id} not found")


if __name__ == "__main__":
    server = Server()
    server.start()
