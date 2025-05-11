#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <arpa/inet.h>  // For sockaddr_in, inet_pton, htons
#include <unistd.h>     // For close(), read(), write()
#include <sys/socket.h> // For socket(), connect(), recv(), send()
#include <json/json.h>  // Include the JSON library
#include "px.cpp"       // Assuming px.cpp has necessary cryptographic implementations

class Client {
private:
    std::string serverHost;
    int serverPort;
    DiffieHellman dh;
    std::vector<uint8_t> sharedSecret;
    std::vector<uint8_t> derivedKey;
    bool running;

    void listenToServer(int clientSocket) {
        while (running) {
            try {
                char buffer[1024];
                int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
                if (bytesReceived <= 0) {
                    std::cerr << "Server closed the connection" << std::endl;
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
                    handleKeyExchange(message);
                }
            } catch (const std::exception &e) {
                std::cerr << "Error listening to server: " << e.what() << std::endl;
                break;
            }
        }
    }

    void sendKeyExchange(int clientSocket) {
        std::cout << "Enter recipient client ID: ";
        int recipientId;
        std::cin >> recipientId;

        Json::Value message;
        message["type"] = "key_exchange_request";
        message["recipient_id"] = recipientId;
        message["sender_public_key"] = dh.exportPublicKey();

        std::string messageStr = Json::writeString(Json::StreamWriterBuilder(), message);
        send(clientSocket, messageStr.c_str(), messageStr.size(), 0);

        std::cout << "Sent key exchange request to client " << recipientId << std::endl;
    }

    void handleKeyExchange(const Json::Value &message) {
        try {
            uint64_t senderPublicKey = std::stoull(message["sender_public_key"].asString(), nullptr, 16);
            sharedSecret = dh.computeSharedSecret(senderPublicKey);

            std::cout << "Shared secret established: ";
            for (uint8_t byte : sharedSecret) {
                printf("%02x", byte);
            }
            std::cout << std::endl;

            // Derive a key from the shared secret using HKDF
            HKDF hkdf;
            std::vector<uint8_t> salt = {0x68, 0x6b, 0x64, 0x66}; // Example salt (hkdf-salt in bytes)
            derivedKey = hkdf.deriveKey(salt, sharedSecret, {}, 32);

            std::cout << "Derived key: ";
            for (uint8_t byte : derivedKey) {
                printf("%02x", byte);
            }
            std::cout << std::endl;

            std::cout << "Both users have now established the shared secret and derived key." << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "Error handling key exchange: " << e.what() << std::endl;
        }
    }

public:
    Client(const std::string &serverHost = "127.0.0.1", int serverPort = 5222)
        : serverHost(serverHost), serverPort(serverPort), running(true) {
        dh.generateParameters();
        dh.generateKeypair();
    }

    void start() {
        int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1) {
            throw std::runtime_error("Failed to create socket");
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(serverPort);
        inet_pton(AF_INET, serverHost.c_str(), &serverAddr.sin_addr);

        try {
            if (connect(clientSocket, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == -1) {
                throw std::runtime_error("Failed to connect to server");
            }

            std::cout << "Connected to server" << std::endl;

            std::thread listenThread(&Client::listenToServer, this, clientSocket);
            sendKeyExchange(clientSocket);

            listenThread.join();
        } catch (const std::exception &e) {
            std::cerr << "Error in client: " << e.what() << std::endl;
        }

        close(clientSocket);
        std::cout << "Client shutting down" << std::endl;
        running = false;
    }
};

int main() {
    try {
        Client client;
        client.start();
    } catch (const std::exception &e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
    return 0;
}
