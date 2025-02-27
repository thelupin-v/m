#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 21
#define MAX_BUFFER_SIZE 1024

// FTP server credentials
const char *username = "admin";
const char *password = "password123";

// Initialize WinSock
void init_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        exit(1);
    }
}

// Create and bind the FTP server socket
SOCKET create_server_socket() {
    SOCKET server_socket;
    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        exit(1);
    }

    if (listen(server_socket, 1) == SOCKET_ERROR) {
        printf("Listen failed\n");
        exit(1);
    }

    return server_socket;
}

// Handle client communication
void handle_client(SOCKET client_socket) {
    char buffer[MAX_BUFFER_SIZE];
    int recv_size;
    
    // Send initial FTP server greeting
    send(client_socket, "220 Welcome to Simple FTP Server\r\n", 33, 0);
    
    // Receive username
    recv_size = recv(client_socket, buffer, MAX_BUFFER_SIZE, 0);
    if (recv_size > 0) {
        buffer[recv_size] = '\0';
        if (strncmp(buffer, "USER ", 5) == 0) {
            send(client_socket, "331 User name okay, need password\r\n", 36, 0);
        }
    }

    // Receive password
    recv_size = recv(client_socket, buffer, MAX_BUFFER_SIZE, 0);
    if (recv_size > 0) {
        buffer[recv_size] = '\0';
        if (strncmp(buffer, "PASS ", 5) == 0) {
            if (strncmp(buffer + 5, password, strlen(password)) == 0) {
                send(client_socket, "230 User logged in, proceed\r\n", 30, 0);
            } else {
                send(client_socket, "530 Login incorrect\r\n", 21, 0);
            }
        }
    }

    // Wait for quit command (QUIT)
    recv_size = recv(client_socket, buffer, MAX_BUFFER_SIZE, 0);
    if (recv_size > 0) {
        buffer[recv_size] = '\0';
        if (strncmp(buffer, "QUIT", 4) == 0) {
            send(client_socket, "221 Goodbye\r\n", 14, 0);
        }
    }

    closesocket(client_socket);
}

int main() {
    SOCKET server_socket, client_socket;
    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);

    // Initialize WinSock
    init_winsock();

    // Create server socket
    server_socket = create_server_socket();
    printf("FTP server listening on port %d...\n", PORT);

    // Wait for client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }

        printf("Client connected\n");

        // Handle the client in a separate function
        handle_client(client_socket);
    }

    // Cleanup
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
