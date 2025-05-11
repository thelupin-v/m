#include <iostream>
#include <string>
#include <thread>
#include <map>
#include <mutex>
#include <cstring>
#include <arpa/inet.h>  // For sockaddr_in, inet_pton, htons
#include <unistd.h>     // For close(), read(), write()
#include <sys/socket.h> // For socket(), bind(), listen(), recv(), send()
#include <json/json.h>  // Include the JSON library
#include "px.cpp"       // Assuming px.cpp has necessary cryptographic implementations

class Server {
private:
    std::string host;
    int port;
    std::map<int, int> clientSockets; // Map of client IDs to their sockets
    std::mutex clientMutex;

    void handleClient(int clientSocket) {
        int clientId = clientSocket; // Using socket FD as unique client ID
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            clientSockets[clientId] = clientSocket;
            std::cout << "New client connected: ID = " << clientId << std::endl;
        }

        try {
            while (true) {
                char buffer[1024];
                int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
                if (bytesReceived <= 0) {
                    // Client disconnected
                    break;
                }

                // Parse JSON message
                Json::CharReaderBuilder reader;
                Json::Value message;
                std::string errs;
                std::string rawMessage(buffer, bytesReceived);
                std::istringstream ss(rawMessage);
                if (!Json::parseFromStream(reader, ss, &message, &errs)) {
                    std::cerr << "Failed to parse message: " << errs << std::endl;
                    continue;
                }

                if (message["type"].asString() == "key_exchange_request") {
                    forwardKeyExchange(clientId, message);
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "Error with client " << clientId << ": " << e.what() << std::endl;
        }

        // Clean up client
        {
            std::lock_guard<std::mutex> lock(clientMutex);
            clientSockets.erase(clientId);
        }
        close(clientSocket);
        std::cout << "Client disconnected: ID = " << clientId << std::endl;
    }

    void forwardKeyExchange(int senderId, const Json::Value &message) {
        int recipientId = message["recipient_id"].asInt();
        std::lock_guard<std::mutex> lock(clientMutex);
        if (clientSockets.find(recipientId) != clientSockets.end()) {
            int recipientSocket = clientSockets[recipientId];
            std::string forwardMessage = Json::writeString(Json::StreamWriterBuilder(), message);
            send(recipientSocket, forwardMessage.c_str(), forwardMessage.size(), 0);
            std::cout << "Forwarded key exchange from client " << senderId << " to client " << recipientId << std::endl;
        } else {
            // Notify sender that recipient is not connected
            int senderSocket = clientSockets[senderId];
            Json::Value errorMsg;
            errorMsg["type"] = "error";
            errorMsg["message"] = "Recipient not connected";
            std::string errorStr = Json::writeString(Json::StreamWriterBuilder(), errorMsg);
            send(senderSocket, errorStr.c_str(), errorStr.size(), 0);
            std::cout << "Error: Recipient client " << recipientId << " not connected" << std::endl;
        }
    }

public:
    Server(const std::string &host = "127.0.0.1", int port = 65432)
        : host(host), port(port) {}

    void start() {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            throw std::runtime_error("Failed to create socket");
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);

        if (bind(serverSocket, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == -1) {
            throw std::runtime_error("Failed to bind");
        }

        if (listen(serverSocket, 5) == -1) {
            throw std::runtime_error("Failed to listen");
        }

        std::cout << "Server started on " << host << ":" << port << std::endl;

        while (true) {
            sockaddr_in clientAddr{};
            socklen_t clientAddrLen = sizeof(clientAddr);
            int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr *>(&clientAddr), &clientAddrLen);
            if (clientSocket == -1) {
                std::cerr << "Failed to accept connection" << std::endl;
                continue;
            }

            std::thread clientThread(&Server::handleClient, this, clientSocket);
            clientThread.detach();
        }
    }
};

int main() {
    try {
        Server server;
        server.start();
    } catch (const std::exception &e) {
        std::cerr << "Server error: " << e.what() << std::endl;
    }
    return 0;
}
