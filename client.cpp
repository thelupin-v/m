/**
 * client.cpp - PX Encrypted Calling Application Client GUI
 * 
 * This client component handles user interface, call establishment,
 * encryption using the custom PX protocol, and Diffie-Hellman key exchange
 * with visualization.
 */

 #include <QApplication>
 #include <QMainWindow>
 #include <QVBoxLayout>
 #include <QHBoxLayout>
 #include <QGridLayout>
 #include <QPushButton>
 #include <QLabel>
 #include <QLineEdit>
 #include <QListWidget>
 #include <QComboBox>
 #include <QGroupBox>
 #include <QMessageBox>
 #include <QInputDialog>
 #include <QTimer>
 #include <QDateTime>
 #include <QScreen>
 #include <QPixmap>
 #include <QPainter>
 #include <QWidget>
 #include <QStyleFactory>
 #include <QTabWidget>
 #include <QCheckBox>
 #include <QDesktopWidget>
 #include <QScrollArea>
 #include <QTextEdit>
 #include <QFontDatabase>
 #include <QThread>
 
 // Network headers
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <poll.h>
 
 // Standard library
 #include <iostream>
 #include <vector>
 #include <map>
 #include <string>
 #include <thread>
 #include <mutex>
 #include <chrono>
 #include <random>
 #include <functional>
 #include <cstring>
 #include <cstdlib>
 #include <cstdint>
 #include <algorithm>
 #include <condition_variable>
 #include <sstream>
 #include <iomanip>
 #include <cmath>
 #include <memory>
 #include <set>
 
 // Audio support with Opus
 extern "C" {
     #include <opus/opus.h>
 }
 
 // Constants
 constexpr int DEFAULT_SERVER_PORT = 8000;
 constexpr int DEFAULT_TURN_PORT = 3478;
 constexpr int MAX_BUFFER_SIZE = 8192;
 constexpr int HEARTBEAT_INTERVAL = 10; // seconds
 constexpr uint16_t PROTOCOL_VERSION = 1;
 constexpr int OPUS_SAMPLE_RATE = 48000;
 constexpr int OPUS_CHANNELS = 1;
 constexpr int OPUS_FRAME_SIZE = 960; // 20ms at 48kHz
 constexpr int DH_KEY_SIZE = 256; // bits
 constexpr int MAX_RETRIES = 5;
 constexpr int RETRY_DELAY = 1000; // milliseconds
 constexpr int CALL_TIMEOUT = 30000; // milliseconds
 
 // Packet types (protocol definition - matches server.cpp)
 enum PacketType {
     REGISTER = 1,
     REGISTER_ACK = 2,
     CALL_REQUEST = 3,
     CALL_RESPONSE = 4,
     CALL_ACCEPT = 5,
     CALL_REJECT = 6,
     CALL_END = 7,
     P2P_ATTEMPT = 8,
     P2P_SUCCESS = 9,
     P2P_FAILURE = 10,
     RELAY_DATA = 11,
     HEARTBEAT = 12,
     HEARTBEAT_ACK = 13,
     ERROR = 14,
     USER_DISCOVERY = 15,
     USER_LIST = 16
 };
 
 // PX Packet Header structure 
 struct PacketHeader {
     uint16_t version;
     uint8_t type;
     uint16_t length;
     uint32_t sender_id;
     uint32_t receiver_id;
     uint32_t call_id;
     uint32_t seq_num;
     uint32_t timestamp;
 };
 
 // Call state
 enum CallState {
     IDLE,
     OUTGOING_CALL,
     INCOMING_CALL,
     CALL_IN_PROGRESS,
     P2P_NEGOTIATING
 };
 
 // Media types
 enum MediaType {
     AUDIO = 0,
     VIDEO = 1,
     SCREEN = 2
 };
 
 // User info structure
 struct UserInfo {
     uint32_t user_id;
     std::string username;
 };
 
 // Call info structure
 struct CallInfo {
     uint32_t call_id;
     uint32_t peer_id;
     std::string peer_username;
     bool is_video;
     bool is_screen_sharing;
     bool is_p2p;
     uint32_t local_seq_num;
     uint32_t remote_seq_num;
     std::chrono::time_point<std::chrono::steady_clock> start_time;
 };
 
 // Forward declarations for encryption methods
 class DHKeyExchange;
 class PXEncryption;
 
 // ----------------
 // UTILITY FUNCTIONS
 // ----------------
 
 // Helper function to convert binary to hex string
 std::string bin2hex(const std::vector<uint8_t>& data) {
     std::stringstream ss;
     ss << std::hex << std::setfill('0');
     for (auto byte : data) {
         ss << std::setw(2) << static_cast<int>(byte);
     }
     return ss.str();
 }
 
 // Helper function to convert hex string to binary
 std::vector<uint8_t> hex2bin(const std::string& hex) {
     std::vector<uint8_t> bytes;
     for (size_t i = 0; i < hex.length(); i += 2) {
         std::string byteString = hex.substr(i, 2);
         uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
         bytes.push_back(byte);
     }
     return bytes;
 }
 
 // Secure random number generator
 class SecureRandom {
 private:
     std::random_device rd;
     std::mt19937 gen;
     
 public:
     SecureRandom() : gen(rd()) {}
     
     template <typename T>
     T getRandomNumber(T min, T max) {
         std::uniform_int_distribution<T> dist(min, max);
         return dist(gen);
     }
     
     std::vector<uint8_t> getRandomBytes(size_t count) {
         std::vector<uint8_t> bytes(count);
         std::uniform_int_distribution<int> dist(0, 255);
         for (size_t i = 0; i < count; ++i) {
             bytes[i] = static_cast<uint8_t>(dist(gen));
         }
         return bytes;
     }
 };
 
 // Global instance of secure random
 SecureRandom secureRandom;
 
 // ----------------
 // DIFFIE-HELLMAN KEY EXCHANGE
 // ----------------
 
 // Diffie-Hellman key exchange implementation
 class DHKeyExchange {
 private:
     // Prime modulus p and base g
     std::vector<uint8_t> p; // Large prime
     std::vector<uint8_t> g; // Generator
     
     // Private key a
     std::vector<uint8_t> privateKey;
     
     // Public keys
     std::vector<uint8_t> publicKey;  // g^a mod p
     std::vector<uint8_t> peerPublicKey; // g^b mod p
     
     // Shared secret
     std::vector<uint8_t> sharedSecret; // (g^b)^a mod p = g^(ab) mod p
     
     // Hash of our public key (for commitment)
     std::vector<uint8_t> publicKeyHash;
     
     // Montgomery modular exponentiation (a^b mod n)
     std::vector<uint8_t> modExp(const std::vector<uint8_t>& base, const std::vector<uint8_t>& exponent, const std::vector<uint8_t>& modulus) {
         if (modulus.size() == 0 || (modulus.size() == 1 && modulus[0] == 0)) {
             throw std::invalid_argument("Modulus cannot be 0");
         }
         
         // Convert to big integers (simple implementation)
         std::vector<uint8_t> result = {1};
         std::vector<uint8_t> baseVal = base;
         std::vector<uint8_t> expVal = exponent;
         
         while (!isZero(expVal)) {
             if (expVal[0] & 1) {
                 result = modMul(result, baseVal, modulus);
             }
             baseVal = modMul(baseVal, baseVal, modulus);
             expVal = divideBy2(expVal);
         }
         
         return result;
     }
     
     // Check if a big integer is zero
     bool isZero(const std::vector<uint8_t>& num) {
         for (auto byte : num) {
             if (byte != 0) {
                 return false;
             }
         }
         return true;
     }
     
     // Divide a big integer by 2
     std::vector<uint8_t> divideBy2(const std::vector<uint8_t>& num) {
         std::vector<uint8_t> result(num.size());
         uint16_t remainder = 0;
         
         for (int i = num.size() - 1; i >= 0; --i) {
             uint16_t current = num[i] + (remainder << 8);
             result[i] = current >> 1;
             remainder = current & 1;
         }
         
         // Remove leading zeros
         while (result.size() > 1 && result.back() == 0) {
             result.pop_back();
         }
         
         return result;
     }
     
     // Modular multiplication (a * b mod n)
     std::vector<uint8_t> modMul(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, const std::vector<uint8_t>& n) {
         std::vector<uint8_t> result(a.size() + b.size(), 0);
         
         // Multiply
         for (size_t i = 0; i < a.size(); ++i) {
             uint16_t carry = 0;
             for (size_t j = 0; j < b.size() || carry; ++j) {
                 uint16_t bValue = (j < b.size()) ? b[j] : 0;
                 uint32_t current = result[i + j] + (uint32_t)a[i] * bValue + carry;
                 result[i + j] = current & 0xFF;
                 carry = current >> 8;
             }
         }
         
         // Remove leading zeros
         while (result.size() > 1 && result.back() == 0) {
             result.pop_back();
         }
         
         // Modulo
         return modDivide(result, n);
     }
     
     // Modular division (a mod n)
     std::vector<uint8_t> modDivide(const std::vector<uint8_t>& a, const std::vector<uint8_t>& n) {
         // Simple mod implementation - just for illustration
         // In a real app, would use a full bignum library
         
         // If a < n, return a
         if (compare(a, n) < 0) {
             return a;
         }
         
         // Subtract n from a until a < n
         std::vector<uint8_t> result = a;
         while (compare(result, n) >= 0) {
             result = subtract(result, n);
         }
         
         return result;
     }
     
     // Compare two big integers (a <=> b)
     int compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
         if (a.size() < b.size()) return -1;
         if (a.size() > b.size()) return 1;
         
         for (int i = a.size() - 1; i >= 0; --i) {
             if (a[i] < b[i]) return -1;
             if (a[i] > b[i]) return 1;
         }
         
         return 0; // Equal
     }
     
     // Subtract b from a
     std::vector<uint8_t> subtract(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
         std::vector<uint8_t> result(a.size(), 0);
         int borrow = 0;
         
         for (size_t i = 0; i < a.size(); ++i) {
             int aValue = a[i];
             int bValue = (i < b.size()) ? b[i] : 0;
             int diff = aValue - bValue - borrow;
             
             if (diff < 0) {
                 diff += 256;
                 borrow = 1;
             } else {
                 borrow = 0;
             }
             
             result[i] = diff;
         }
         
         // Remove leading zeros
         while (result.size() > 1 && result.back() == 0) {
             result.pop_back();
         }
         
         return result;
     }
     
     // SHA-256 hash function
     std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
         // In a real application, this would call a proper SHA-256 implementation
         // For this example, we'll create a simplified hash
         std::vector<uint8_t> hash(32, 0); // 256 bits = 32 bytes
         
         // XOR-based simple hash (NOT SECURE! Just for demonstration)
         for (size_t i = 0; i < data.size(); ++i) {
             hash[i % 32] ^= data[i];
             // Perform a simple rotation
             uint8_t temp = hash[0];
             for (int j = 0; j < 31; ++j) {
                 hash[j] = hash[j+1];
             }
             hash[31] = temp;
         }
         
         return hash;
     }
     
     // Initialize the prime and generator
     void initPrimeAndGenerator() {
         // RFC 3526 MODP Group 14 (2048 bits)
         // In a real implementation, you would hard-code the prime or use a standard library
         std::string primeHex = 
             "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
             "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
             "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
             "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
             "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
             "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
             "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
             "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
             "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
             "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
             "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
         
         p = hex2bin(primeHex);
         g = {2}; // Generator is 2
     }
     
 public:
     DHKeyExchange() {
         initPrimeAndGenerator();
     }
     
     // Reset for a new key exchange
     void reset() {
         // Generate new private key (a)
         privateKey = secureRandom.getRandomBytes(DH_KEY_SIZE / 8);
         
         // Calculate public key (g^a mod p)
         publicKey = modExp(g, privateKey, p);
         
         // Calculate hash of public key for commitment
         publicKeyHash = sha256(publicKey);
         
         // Clear peer public key and shared secret
         peerPublicKey.clear();
         sharedSecret.clear();
     }
     
     // Get our public key hash (for commitment)
     std::vector<uint8_t> getPublicKeyHash() const {
         return publicKeyHash;
     }
     
     // Get our public key
     std::vector<uint8_t> getPublicKey() const {
         return publicKey;
     }
     
     // Set peer's public key and compute shared secret
     bool setPeerPublicKey(const std::vector<uint8_t>& key) {
         peerPublicKey = key;
         
         // Calculate shared secret (g^b)^a mod p = g^(ab) mod p
         try {
             sharedSecret = modExp(peerPublicKey, privateKey, p);
             return true;
         } catch (const std::exception& e) {
             std::cerr << "Error computing shared secret: " << e.what() << std::endl;
             return false;
         }
     }
     
     // Verify the peer's public key against previously received hash
     bool verifyPeerPublicKey(const std::vector<uint8_t>& key, const std::vector<uint8_t>& hash) {
         return sha256(key) == hash;
     }
     
     // Get shared secret
     std::vector<uint8_t> getSharedSecret() const {
         return sharedSecret;
     }
     
     // Convert shared secret to emoji visualization
     std::vector<int> getEmojiVisualization() const {
         // Use the shared secret to generate 4 emoji indices
         // Each emoji index is in range 0-332 (total 333 different emojis)
         std::vector<int> emojiIndices;
         
         if (sharedSecret.empty()) {
             return emojiIndices;
         }
         
         // Use the first 4 bytes of the shared secret hash to select emojis
         std::vector<uint8_t> secretHash = sha256(sharedSecret);
         
         for (int i = 0; i < 4; i++) {
             // Use 4 bytes from the hash (more entropy)
             uint32_t value = 0;
             for (int j = 0; j < 4; j++) {
                 value = (value << 8) | secretHash[i*4 + j];
             }
             // Map to 0-332 range
             emojiIndices.push_back(value % 333);
         }
         
         return emojiIndices;
     }
 };
 
 // ----------------
 // PX ENCRYPTION
 // ----------------
 
 // PX Encryption implementation
 class PXEncryption {
 private:
     std::vector<uint8_t> key;
     std::vector<uint8_t> iv;
     
     // Simple XOR-based encryption (for demonstration - in real app would use AES-GCM or similar)
     std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data) {
         if (key.empty()) {
             throw std::runtime_error("Encryption key not set");
         }
         
         std::vector<uint8_t> result = data;
         for (size_t i = 0; i < data.size(); ++i) {
             result[i] = data[i] ^ key[i % key.size()] ^ iv[(i + 1) % iv.size()];
         }
         
         return result;
     }
     
 public:
     PXEncryption() {}
     
     // Initialize with key from DH key exchange and a random IV
     void init(const std::vector<uint8_t>& dhKey) {
         // Use the first 32 bytes of the DH shared secret as our key
         // In a real application, you would derive proper encryption keys using HKDF
         key = dhKey;
         if (key.size() > 32) {
             key.resize(32);
         }
         
         // Generate a random IV
         iv = secureRandom.getRandomBytes(16);
     }
     
     // Reset everything
     void reset() {
         key.clear();
         iv.clear();
     }
     
     // Encrypt data
     std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
         // In a real application, this would be AES-GCM or similar
         // For this example, we use simple XOR with the key and IV
         return xorEncrypt(plaintext);
     }
     
     // Decrypt data
     std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
         // XOR is symmetric, so encryption and decryption are the same
         return xorEncrypt(ciphertext);
     }
     
     // Get the current IV (for packet headers)
     std::vector<uint8_t> getIV() const {
         return iv;
     }
 };
 
 // ----------------
 // NETWORK HANDLER
 // ----------------
 
 // Network communication handler
 class NetworkHandler : public QObject {
     Q_OBJECT
     
 private:
     int sock;
     std::string serverAddress;
     int serverPort;
     std::string turnAddress;
     int turnPort;
     
     uint32_t clientId;
     std::string username;
     bool registered;
     
     QTimer* heartbeatTimer;
     QTimer* timeoutTimer;
     
     std::thread networkThread;
     std::atomic<bool> running;
     std::mutex sendMutex;
     
     // Connection to TURN server
     int turnSock;
     sockaddr_in turnAddr;
     bool turnConnected;
     
     // Sequence numbers for packets
     uint32_t nextSeqNum;
     
     // Call state
     CallState callState;
     CallInfo currentCall;
     std::map<uint32_t, UserInfo> knownUsers;
     
     // Encryption and key exchange
     DHKeyExchange dhKeyExchange;
     PXEncryption pxEncryption;
     
 public:
     NetworkHandler(QObject* parent = nullptr) 
         : QObject(parent), sock(-1), serverPort(DEFAULT_SERVER_PORT),
           turnPort(DEFAULT_TURN_PORT), clientId(0), registered(false),
           heartbeatTimer(nullptr), timeoutTimer(nullptr), running(false),
           turnSock(-1), turnConnected(false), nextSeqNum(1),
           callState(IDLE) {
         
         // Initialize timers
         heartbeatTimer = new QTimer(this);
         connect(heartbeatTimer, &QTimer::timeout, this, &NetworkHandler::sendHeartbeat);
         
         timeoutTimer = new QTimer(this);
         connect(timeoutTimer, &QTimer::timeout, this, &NetworkHandler::handleCallTimeout);
     }
     
     ~NetworkHandler() {
         disconnect();
     }
     
     // Connect to server
     bool connect(const std::string& server, int port, const std::string& turn, int turnP) {
         serverAddress = server;
         serverPort = port;
         turnAddress = turn;
         turnPort = turnP;
         
         // Create UDP socket
         sock = socket(AF_INET, SOCK_DGRAM, 0);
         if (sock < 0) {
             emit error("Failed to create socket");
             return false;
         }
         
         // Set socket to non-blocking
         int flags = fcntl(sock, F_GETFL, 0);
         fcntl(sock, F_SETFL, flags | O_NONBLOCK);
         
         // Start network thread
         running = true;
         networkThread = std::thread(&NetworkHandler::networkLoop, this);
         
         return true;
     }
     
     // Disconnect from server
     void disconnect() {
         // Stop timers
         heartbeatTimer->stop();
         timeoutTimer->stop();
         
         // Stop network thread
         running = false;
         if (networkThread.joinable()) {
             networkThread.join();
         }
         
         // Close sockets
         if (sock >= 0) {
             close(sock);
             sock = -1;
         }
         
         if (turnSock >= 0) {
             close(turnSock);
             turnSock = -1;
         }
         
         // Reset state
         registered = false;
         turnConnected = false;
         callState = IDLE;
         nextSeqNum = 1;
     }
     
     // Register with server
     bool registerWithServer(const std::string& user) {
         if (sock < 0) {
             emit error("Not connected to server");
             return false;
         }
         
         username = user;
         
         // Create REGISTER packet
         size_t packetSize = sizeof(PacketHeader) + username.size();
         std::vector<char> packet(packetSize);
         
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = REGISTER,
             .length = static_cast<uint16_t>(packetSize),
             .sender_id = 0, // Will be assigned by server
             .receiver_id = 0, // Server
             .call_id = 0,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         memcpy(packet.data(), &header, sizeof(PacketHeader));
         memcpy(packet.data() + sizeof(PacketHeader), username.c_str(), username.size());
         
         // Send registration packet
         return sendPacket(packet.data(), packet.size());
     }
     
     // Request user list
     bool requestUserList() {
         if (!registered) {
             emit error("Not registered with server");
             return false;
         }
         
         // Create USER_DISCOVERY packet
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = USER_DISCOVERY,
             .length = sizeof(PacketHeader),
             .sender_id = clientId,
             .receiver_id = 0, // Server
             .call_id = 0,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         return sendPacket(reinterpret_cast<char*>(&header), sizeof(header));
     }
     
     // Start a call to a user
     bool startCall(uint32_t userId, bool video, bool screenSharing) {
         if (!registered || clientId == 0) {
             emit error("Not registered with server");
             return false;
         }
         
         if (callState != IDLE) {
             emit error("Already in a call");
             return false;
         }
         
         if (knownUsers.find(userId) == knownUsers.end()) {
             emit error("Unknown user ID");
             return false;
         }
         
         // Initialize key exchange
         dhKeyExchange.reset();
         
         // Create CALL_REQUEST packet with public key hash commitment
         std::vector<uint8_t> publicKeyHash = dhKeyExchange.getPublicKeyHash();
         
         size_t packetSize = sizeof(PacketHeader) + publicKeyHash.size() + 1;
         std::vector<char> packet(packetSize);
         
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = CALL_REQUEST,
             .length = static_cast<uint16_t>(packetSize),
             .sender_id = clientId,
             .receiver_id = userId,
             .call_id = 0, // Will be assigned by server
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         memcpy(packet.data(), &header, sizeof(PacketHeader));
         
         // Add call options (video/screen sharing flags)
         uint8_t options = 0;
         if (video) options |= 0x01;
         if (screenSharing) options |= 0x02;
         packet[sizeof(PacketHeader)] = options;
         
         // Add public key hash (commitment)
         memcpy(packet.data() + sizeof(PacketHeader) + 1, publicKeyHash.data(), publicKeyHash.size());
         
         // Update call state
         callState = OUTGOING_CALL;
         currentCall.peer_id = userId;
         currentCall.peer_username = knownUsers[userId].username;
         currentCall.is_video = video;
         currentCall.is_screen_sharing = screenSharing;
         currentCall.is_p2p = false;
         currentCall.local_seq_num = 0;
         currentCall.remote_seq_num = 0;
         
         // Start timeout timer
         timeoutTimer->start(CALL_TIMEOUT);
         
         // Send call request
         return sendPacket(packet.data(), packet.size());
     }
     
     // Accept an incoming call
     bool acceptCall(bool video, bool screenSharing) {
         if (callState != INCOMING_CALL) {
             emit error("No incoming call to accept");
             return false;
         }
         
         // Generate and send our public key (step 2 of 3-way DH exchange)
         std::vector<uint8_t> publicKey = dhKeyExchange.getPublicKey();
         
         size_t packetSize = sizeof(PacketHeader) + publicKey.size() + 1;
         std::vector<char> packet(packetSize);
         
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = CALL_ACCEPT,
             .length = static_cast<uint16_t>(packetSize),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         memcpy(packet.data(), &header, sizeof(PacketHeader));
         
         // Add call options
         uint8_t options = 0;
         if (video) options |= 0x01;
         if (screenSharing) options |= 0x02;
         packet[sizeof(PacketHeader)] = options;
         
         // Add public key
         memcpy(packet.data() + sizeof(PacketHeader) + 1, publicKey.data(), publicKey.size());
         
         // Update call info
         currentCall.is_video = video;
         currentCall.is_screen_sharing = screenSharing;
         
         // Start P2P negotiation
         callState = P2P_NEGOTIATING;
         
         // Stop timeout timer
         timeoutTimer->stop();
         
         // Start call timer
         currentCall.start_time = std::chrono::steady_clock::now();
         
         // Send acceptance
         return sendPacket(packet.data(), packet.size());
     }
     
     // Reject an incoming call
     bool rejectCall() {
         if (callState != INCOMING_CALL) {
             emit error("No incoming call to reject");
             return false;
         }
         
         // Create CALL_REJECT packet
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = CALL_REJECT,
             .length = sizeof(PacketHeader),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         // Reset call state
         callState = IDLE;
         
         // Stop timeout timer
         timeoutTimer->stop();
         
         // Send rejection
         return sendPacket(reinterpret_cast<char*>(&header), sizeof(header));
     }
     
     // End current call
     bool endCall() {
         if (callState == IDLE) {
             return true; // No call to end
         }
         
         // Create CALL_END packet
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = CALL_END,
             .length = sizeof(PacketHeader),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         // Reset call state and encryption
         callState = IDLE;
         pxEncryption.reset();
         
         // Stop timers
         timeoutTimer->stop();
         
         // Send call end
         return sendPacket(reinterpret_cast<char*>(&header), sizeof(header));
     }
     
     // Send encrypted media data
     bool sendMediaData(MediaType type, const std::vector<uint8_t>& data) {
         if (callState != CALL_IN_PROGRESS) {
             return false;
         }
         
         // Encrypt the media data
         std::vector<uint8_t> encrypted = pxEncryption.encrypt(data);
         
         // Create packet header
         size_t packetSize = sizeof(PacketHeader) + 1 + encrypted.size(); // +1 for media type
         std::vector<char> packet(packetSize);
         
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = RELAY_DATA,
             .length = static_cast<uint16_t>(packetSize),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = currentCall.local_seq_num++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         memcpy(packet.data(), &header, sizeof(PacketHeader));
         
         // Add media type
         packet[sizeof(PacketHeader)] = static_cast<char>(type);
         
         // Add encrypted data
         memcpy(packet.data() + sizeof(PacketHeader) + 1, encrypted.data(), encrypted.size());
         
         // Send packet
         return sendPacket(packet.data(), packet.size());
     }
     
     // Try to establish P2P connection
     bool tryP2PConnection() {
         if (callState != P2P_NEGOTIATING && callState != CALL_IN_PROGRESS) {
             return false;
         }
         
         // In a real application, this would collect local network information
         // and send it to the peer for connection attempts
         
         // Create P2P_ATTEMPT packet
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = P2P_ATTEMPT,
             .length = sizeof(PacketHeader),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         // Send packet
         return sendPacket(reinterpret_cast<char*>(&header), sizeof(header));
     }
     
     // Complete the key exchange (send our public key)
     bool completeKeyExchange() {
         if (callState != P2P_NEGOTIATING) {
             return false;
         }
         
         // Get our public key (step 3 of 3-way DH exchange)
         std::vector<uint8_t> publicKey = dhKeyExchange.getPublicKey();
         
         // Create packet with our public key
         size_t packetSize = sizeof(PacketHeader) + publicKey.size();
         std::vector<char> packet(packetSize);
         
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = P2P_SUCCESS,
             .length = static_cast<uint16_t>(packetSize),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         memcpy(packet.data(), &header, sizeof(PacketHeader));
         memcpy(packet.data() + sizeof(PacketHeader), publicKey.data(), publicKey.size());
         
         // Initialize encryption with the shared secret
         std::vector<uint8_t> sharedSecret = dhKeyExchange.getSharedSecret();
         pxEncryption.init(sharedSecret);
         
         // Update call state
         callState = CALL_IN_PROGRESS;
         
         // Send packet
         return sendPacket(packet.data(), packet.size());
     }
     
     // Get list of known users
     std::map<uint32_t, UserInfo> getUsers() const {
         return knownUsers;
     }
     
     // Get current call information
     CallInfo getCurrentCall() const {
         return currentCall;
     }
     
     // Get current call state
     CallState getCallState() const {
         return callState;
     }
     
     // Get emoji verification code
     std::vector<int> getEmojiVerification() const {
         return dhKeyExchange.getEmojiVisualization();
     }
     
 signals:
     void registered(uint32_t client_id);
     void error(const QString& message);
     void userListReceived();
     void incomingCall(uint32_t caller_id, const QString& caller_name);
     void callAccepted();
     void callRejected();
     void callEnded();
     void p2pEstablished();
     void mediaReceived(int type, const QByteArray& data);
     void keyExchangeCompleted();
     
 private slots:
     // Send heartbeat to server
     void sendHeartbeat() {
         if (!registered) {
             return;
         }
         
         // Create HEARTBEAT packet
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = HEARTBEAT,
             .length = sizeof(PacketHeader),
             .sender_id = clientId,
             .receiver_id = 0, // Server
             .call_id = 0,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         sendPacket(reinterpret_cast<char*>(&header), sizeof(header));
     }
     
     // Handle call timeout
     void handleCallTimeout() {
         if (callState == OUTGOING_CALL || callState == INCOMING_CALL) {
             // Call timed out
             emit error("Call timed out");
             callState = IDLE;
             timeoutTimer->stop();
         }
     }
     
 private:
     // Network thread loop
     void networkLoop() {
         char buffer[MAX_BUFFER_SIZE];
         struct sockaddr_in sender_addr;
         socklen_t sender_len = sizeof(sender_addr);
         
         struct pollfd fds[1];
         fds[0].fd = sock;
         fds[0].events = POLLIN;
         
         while (running) {
             int ret = poll(fds, 1, 100); // Poll with 100ms timeout
             
             if (ret < 0) {
                 // Error in poll
                 std::cerr << "Poll error" << std::endl;
                 break;
             }
             
             if (ret == 0) {
                 // Timeout - no data
                 continue;
             }
             
             if (fds[0].revents & POLLIN) {
                 // Data available
                 ssize_t received = recvfrom(sock, buffer, MAX_BUFFER_SIZE, 0,
                                            (struct sockaddr*)&sender_addr, &sender_len);
                 
                 if (received > 0) {
                     processIncomingPacket(buffer, received);
                 }
             }
         }
     }
     
     // Send packet to server
     bool sendPacket(const char* data, size_t size) {
         if (sock < 0) {
             return false;
         }
         
         // Create server address
         struct sockaddr_in server_addr;
         memset(&server_addr, 0, sizeof(server_addr));
         server_addr.sin_family = AF_INET;
         server_addr.sin_port = htons(serverPort);
         
         if (inet_pton(AF_INET, serverAddress.c_str(), &server_addr.sin_addr) <= 0) {
             emit error("Invalid server address");
             return false;
         }
         
         // Lock to prevent multiple threads from sending simultaneously
         std::lock_guard<std::mutex> lock(sendMutex);
         
         // Send packet
         ssize_t sent = sendto(sock, data, size, 0,
                              (struct sockaddr*)&server_addr, sizeof(server_addr));
         
         return sent == size;
     }
     
     // Process an incoming packet
     void processIncomingPacket(const char* buffer, size_t size) {
         if (size < sizeof(PacketHeader)) {
             return;
         }
         
         // Parse header
         PacketHeader header;
         memcpy(&header, buffer, sizeof(PacketHeader));
         
         // Validate header
         if (header.version != PROTOCOL_VERSION || header.length > size) {
             return;
         }
         
         // Process packet based on type
         switch (header.type) {
             case REGISTER_ACK:
                 processRegisterAck(buffer, size);
                 break;
                 
             case USER_LIST:
                 processUserList(buffer, size);
                 break;
                 
             case CALL_REQUEST:
                 processCallRequest(buffer, size);
                 break;
                 
             case CALL_ACCEPT:
                 processCallAccept(buffer, size);
                 break;
                 
             case CALL_REJECT:
                 processCallReject(buffer, size);
                 break;
                 
             case CALL_END:
                 processCallEnd(buffer, size);
                 break;
                 
             case P2P_ATTEMPT:
                 processP2PAttempt(buffer, size);
                 break;
                 
             case P2P_SUCCESS:
                 processP2PSuccess(buffer, size);
                 break;
                 
             case P2P_FAILURE:
                 processP2PFailure(buffer, size);
                 break;
                 
             case RELAY_DATA:
                 processRelayData(buffer, size);
                 break;
                 
             case HEARTBEAT_ACK:
                 // Nothing to do for heartbeat acknowledgment
                 break;
                 
             case ERROR:
                 processError(buffer, size);
                 break;
                 
             default:
                 std::cerr << "Unknown packet type: " << static_cast<int>(header.type) << std::endl;
                 break;
         }
     }
     
     // Process REGISTER_ACK
     void processRegisterAck(const char* buffer, size_t size) {
         if (size < sizeof(PacketHeader) + sizeof(uint32_t)) {
             return;
         }
         
         // Extract client ID
         uint32_t id;
         memcpy(&id, buffer + sizeof(PacketHeader), sizeof(uint32_t));
         
         // Update state
         clientId = id;
         registered = true;
         
         // Start heartbeat timer
         heartbeatTimer->start(HEARTBEAT_INTERVAL * 1000);
         
         // Request user list
         requestUserList();
         
         // Notify UI
         emit registered(clientId);
     }
     
     // Process USER_LIST
     void processUserList(const char* buffer, size_t size) {
         if (size <= sizeof(PacketHeader)) {
             return;
         }
         
         // Extract user list
         std::string userListStr(buffer + sizeof(PacketHeader), size - sizeof(PacketHeader));
         
         // Parse user list (format: "username:id;username:id;...")
         knownUsers.clear();
         
         std::istringstream iss(userListStr);
         std::string entry;
         while (std::getline(iss, entry, ';')) {
             size_t colonPos = entry.find(':');
             if (colonPos != std::string::npos) {
                 std::string name = entry.substr(0, colonPos);
                 uint32_t id = std::stoul(entry.substr(colonPos + 1));
                 
                 UserInfo info;
                 info.user_id = id;
                 info.username = name;
                 knownUsers[id] = info;
             }
         }
         
         // Notify UI
         emit userListReceived();
     }
     
     // Process CALL_REQUEST
     void processCallRequest(const char* buffer, size_t size) {
         if (size < sizeof(PacketHeader) + 1) {
             return;
         }
         
         PacketHeader* header = (PacketHeader*)buffer;
         
         // Reject call if already in a call
         if (callState != IDLE) {
             // Send rejection
             PacketHeader rejectHeader = {
                 .version = PROTOCOL_VERSION,
                 .type = CALL_REJECT,
                 .length = sizeof(PacketHeader),
                 .sender_id = clientId,
                 .receiver_id = header->sender_id,
                 .call_id = header->call_id,
                 .seq_num = nextSeqNum++,
                 .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
             };
             
             sendPacket(reinterpret_cast<char*>(&rejectHeader), sizeof(rejectHeader));
             return;
         }
         
         // Parse call options
         uint8_t options = buffer[sizeof(PacketHeader)];
         bool isVideo = (options & 0x01) != 0;
         bool isScreenSharing = (options & 0x02) != 0;
         
         // Extract caller's public key hash (for validation later)
         size_t hashSize = size - sizeof(PacketHeader) - 1;
         std::vector<uint8_t> peerPublicKeyHash(hashSize);
         memcpy(peerPublicKeyHash.data(), buffer + sizeof(PacketHeader) + 1, hashSize);
         
         // Initialize key exchange
         dhKeyExchange.reset();
         
         // Update call state
         callState = INCOMING_CALL;
         currentCall.call_id = header->call_id;
         currentCall.peer_id = header->sender_id;
         currentCall.peer_username = knownUsers[header->sender_id].username;
         currentCall.is_video = isVideo;
         currentCall.is_screen_sharing = isScreenSharing;
         currentCall.is_p2p = false;
         
         // Start timeout timer
         timeoutTimer->start(CALL_TIMEOUT);
         
         // Notify UI
         emit incomingCall(header->sender_id, QString::fromStdString(currentCall.peer_username));
     }
     
     // Process CALL_ACCEPT
     void processCallAccept(const char* buffer, size_t size) {
         if (size < sizeof(PacketHeader) + 1 || callState != OUTGOING_CALL) {
             return;
         }
         
         PacketHeader* header = (PacketHeader*)buffer;
         
         // Parse call options
         uint8_t options = buffer[sizeof(PacketHeader)];
         bool isVideo = (options & 0x01) != 0;
         bool isScreenSharing = (options & 0x02) != 0;
         
         // Extract peer's public key
         size_t keySize = size - sizeof(PacketHeader) - 1;
         std::vector<uint8_t> peerPublicKey(keySize);
         memcpy(peerPublicKey.data(), buffer + sizeof(PacketHeader) + 1, keySize);
         
         // Set peer's public key in our DH exchange
         dhKeyExchange.setPeerPublicKey(peerPublicKey);
         
         // Update call state
         callState = P2P_NEGOTIATING;
         currentCall.call_id = header->call_id;
         currentCall.is_video = isVideo;
         currentCall.is_screen_sharing = isScreenSharing;
         currentCall.start_time = std::chrono::steady_clock::now();
         
         // Stop timeout timer
         timeoutTimer->stop();
         
         // Send our public key to complete the exchange
         completeKeyExchange();
         
         // Start P2P negotiation
         tryP2PConnection();
         
         // Notify UI
         emit callAccepted();
     }
     
     // Process CALL_REJECT
     void processCallReject(const char* buffer, size_t size) {
         if (callState != OUTGOING_CALL) {
             return;
         }
         
         // Reset call state
         callState = IDLE;
         
         // Stop timeout timer
         timeoutTimer->stop();
         
         // Notify UI
         emit callRejected();
     }
     
     // Process CALL_END
     void processCallEnd(const char* buffer, size_t size) {
         if (callState == IDLE) {
             return;
         }
         
         PacketHeader* header = (PacketHeader*)buffer;
         
         // Only accept CALL_END for current call
         if (header->call_id != currentCall.call_id) {
             return;
         }
         
         // Reset call state and encryption
         callState = IDLE;
         pxEncryption.reset();
         
         // Stop timers
         timeoutTimer->stop();
         
         // Notify UI
         emit callEnded();
     }
     
     // Process P2P_ATTEMPT
     void processP2PAttempt(const char* buffer, size_t size) {
         if (callState != P2P_NEGOTIATING && callState != CALL_IN_PROGRESS) {
             return;
         }
         
         // In a real application, this would contain connection information
         // and would attempt to establish a direct P2P connection
         
         // For now, just acknowledge that relay mode will be used
         PacketHeader header = {
             .version = PROTOCOL_VERSION,
             .type = P2P_FAILURE,
             .length = sizeof(PacketHeader),
             .sender_id = clientId,
             .receiver_id = currentCall.peer_id,
             .call_id = currentCall.call_id,
             .seq_num = nextSeqNum++,
             .timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count() / 1000000)
         };
         
         sendPacket(reinterpret_cast<char*>(&header), sizeof(header));
     }
     
     // Process P2P_SUCCESS
     void processP2PSuccess(const char* buffer, size_t size) {
         if (callState != P2P_NEGOTIATING) {
             return;
         }
         
         PacketHeader* header = (PacketHeader*)buffer;
         
         // Extract peer's public key
         size_t keySize = size - sizeof(PacketHeader);
         std::vector<uint8_t> peerPublicKey(keySize);
         memcpy(peerPublicKey.data(), buffer + sizeof(PacketHeader), keySize);
         
         // Verify and set peer's public key
         if (!dhKeyExchange.setPeerPublicKey(peerPublicKey)) {
             emit error("Failed to compute shared secret");
             endCall();
             return;
         }
         
         // Initialize encryption with the shared secret
         std::vector<uint8_t> sharedSecret = dhKeyExchange.getSharedSecret();
         pxEncryption.init(sharedSecret);
         
         // Update call state
         callState = CALL_IN_PROGRESS;
         currentCall.is_p2p = false; // Using relay for now
         
         // Notify UI of encryption establishment
         emit keyExchangeCompleted();
         
         // Notify UI of call establishment
         emit p2pEstablished();
     }
     
     // Process P2P_FAILURE
     void processP2PFailure(const char* buffer, size_t size) {
         if (callState != P2P_NEGOTIATING && callState != CALL_IN_PROGRESS) {
             return;
         }
         
         // Update call state to use relay
         callState = CALL_IN_PROGRESS;
         currentCall.is_p2p = false;
         
         // Notify UI
         emit p2pEstablished();
     }
     
     // Process RELAY_DATA
     void processRelayData(const char* buffer, size_t size) {
         if (callState != CALL_IN_PROGRESS || size <= sizeof(PacketHeader) + 1) {
             return;
         }
         
         PacketHeader* header = (PacketHeader*)buffer;
         
         // Check if packet is for current call
         if (header->call_id != currentCall.call_id) {
             return;
         }
         
         // Get media type
         MediaType mediaType = static_cast<MediaType>(buffer[sizeof(PacketHeader)]);
         
         // Get encrypted data
         size_t dataSize = size - sizeof(PacketHeader) - 1;
         std::vector<uint8_t> encryptedData(dataSize);
         memcpy(encryptedData.data(), buffer + sizeof(PacketHeader) + 1, dataSize);
         
         // Decrypt data
         std::vector<uint8_t> decryptedData = pxEncryption.decrypt(encryptedData);
         
         // Convert to QByteArray for signal
         QByteArray data(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
         
         // Emit signal with decrypted data
         emit mediaReceived(static_cast<int>(mediaType), data);
     }
     
     // Process ERROR
     void processError(const char* buffer, size_t size) {
         if (size <= sizeof(PacketHeader)) {
             return;
         }
         
         // Extract error message
         std::string errorMsg(buffer + sizeof(PacketHeader), size - sizeof(PacketHeader));
         
         // Notify UI
         emit error(QString::fromStdString(errorMsg));
     }
 };
 
 // ----------------
 // EMOJI VISUALIZATION
 // ----------------
 
 // Emoji representation for key verification
 class EmojiVisualizer : public QWidget {
     Q_OBJECT
     
 private:
     std::vector<int> emojiIndices;
     QStringList emojiList;
     
 public:
     EmojiVisualizer(QWidget* parent = nullptr) : QWidget(parent) {
         initEmojis();
     }
     
     void setEmojiIndices(const std::vector<int>& indices) {
         emojiIndices = indices;
         update();
     }
     
     QSize sizeHint() const override {
         return QSize(400, 100);
     }
     
 protected:
     void paintEvent(QPaintEvent* event) override {
         Q_UNUSED(event);
         
         QPainter painter(this);
         painter.setRenderHint(QPainter::Antialiasing);
         
         // Background
         painter.fillRect(rect(), QColor(240, 240, 240));
         
         // Draw emojis
         if (emojiIndices.empty()) {
             painter.drawText(rect(), Qt::AlignCenter, "Waiting for key exchange...");
             return;
         }
         
         int emojiWidth = width() / emojiIndices.size();
         int emojiHeight = height();
         
         for (size_t i = 0; i < emojiIndices.size(); ++i) {
             int index = emojiIndices[i];
             if (index >= 0 && index < emojiList.size()) {
                 QRect emojiRect(i * emojiWidth, 0, emojiWidth, emojiHeight);
                 painter.drawText(emojiRect, Qt::AlignCenter, emojiList[index]);
                 
                 // Draw emoji name below
                 QFont nameFont = painter.font();
                 nameFont.setPointSize(8);
                 painter.setFont(nameFont);
                 QRect nameRect(i * emojiWidth, emojiHeight - 20, emojiWidth, 20);
                 painter.drawText(nameRect, Qt::AlignCenter, getEmojiName(index));
                 
                 // Reset font
                 nameFont.setPointSize(12);
                 painter.setFont(nameFont);
             }
         }
     }
     
 private:
     void initEmojis() {
         // This is a subset of emojis (ideally would have 333 distinct ones)
         emojiList << "😀" << "😁" << "😂" << "🤣" << "😃" << "😄" << "😅" << "😆"
                   << "😉" << "😊" << "😋" << "😎" << "😍" << "😘" << "😗" << "😙"
                   << "😚" << "🙂" << "🤗" << "🤔" << "😐" << "😑" << "😶" << "🙄"
                   << "😏" << "😣" << "😥" << "😮" << "🤐" << "😯" << "😪" << "😫"
                   << "😴" << "😌" << "🤓" << "😛" << "😜" << "😝" << "🤤" << "😒"
                   << "😓" << "😔" << "😕" << "🙃" << "🤑" << "😲" << "☹️" << "🙁"
                   << "😖" << "😞" << "😟" << "😤" << "😢" << "😭" << "😦" << "😧"
                   << "😨" << "😩" << "😬" << "😰" << "😱" << "😳" << "😵" << "😡"
                   << "😠" << "😷" << "🤒" << "🤕" << "🤢" << "🤧" << "😇" << "🤠"
                   << "🤡" << "🤥" << "🤫" << "🤭" << "🧐" << "🤯" << "🤪" << "🤬"
                   << "🧡" << "💛" << "💚" << "💙" << "💜" << "🖤" << "💔" << "❤️"
                   << "💕" << "💞" << "💓" << "💗" << "💖" << "💘" << "💝" << "💟"
                   << "☮️" << "✝️" << "☪️" << "🕉" << "☸️" << "✡️" << "🔯" << "🕎"
                   << "☯️" << "☦️" << "🛐" << "⛎" << "♈️" << "♉️" << "♊️" << "♋️"
                   << "♌️" << "♍️" << "♎️" << "♏️" << "♐️" << "♑️" << "♒️" << "♓️"
                   << "🆔" << "⚛️" << "🉑" << "☢️" << "☣️" << "📴" << "📳" << "🈶"
                   << "🈚️" << "🈸" << "🈺" << "🈷️" << "✴️" << "🆚" << "💮" << "🉐"
                   << "㊙️" << "㊗️" << "🈴" << "🈵" << "🈹" << "🈲" << "🅰️" << "🅱️"
                   << "🆎" << "🆑" << "🅾️" << "🆘" << "❌" << "⭕️" << "🛑" << "⛔️"
                   << "📛" << "🚫" << "💯" << "💢" << "♨️" << "🚷" << "🚯" << "🚳"
                   << "🚱" << "🔞" << "📵" << "🚭" << "❗️" << "❕" << "❓" << "❔"
                   << "‼️" << "⁉️" << "🔅" << "🔆" << "〽️" << "⚠️" << "🚸" << "🔱"
                   << "⚜️" << "🔰" << "♻️" << "✅" << "🈯️" << "💹" << "❇️" << "✳️"
                   << "❎" << "🌐" << "💠" << "Ⓜ️" << "🌀" << "💤" << "🏧" << "🚾"
                   << "♿️" << "🅿️" << "🈳" << "🈂️" << "🛂" << "🛃" << "🛄" << "🛅"
                   << "🚹" << "🚺" << "🚼" << "🚻" << "🚮" << "🎦" << "📶" << "🈁"
                   << "🔣" << "ℹ️" << "🔤" << "🔡" << "🔠" << "🆖" << "🆗" << "🆙"
                   << "🆒" << "🆕" << "🆓" << "0️⃣" << "1️⃣" << "2️⃣" << "3️⃣" << "4️⃣"
                   << "5️⃣" << "6️⃣" << "7️⃣" << "8️⃣" << "9️⃣" << "🔟" << "🔢" << "#️⃣"
                   << "*️⃣" << "▶️" << "⏸" << "⏯" << "⏹" << "⏺" << "⏭" << "⏮"
                   << "⏩" << "⏪" << "⏫" << "⏬" << "◀️" << "🔼" << "🔽" << "➡️"
                   << "⬅️" << "⬆️" << "⬇️" << "↗️" << "↘️" << "↙️" << "↖️" << "↕️"
                   << "↔️" << "↪️" << "↩️" << "⤴️" << "⤵️" << "🔀" << "🔁" << "🔂"
                   << "🔄" << "🔃" << "🎵" << "🎶" << "➕" << "➖" << "➗" << "✖️"
                   << "💲" << "💱" << "™️" << "©️" << "®️" << "〰️" << "➰" << "➿"
                   << "🔚" << "🔙" << "🔛" << "🔝" << "🔜" << "✔️" << "☑️" << "🔘"
                   << "⚪️" << "⚫️" << "🔴" << "🔵" << "🔺" << "🔻" << "🔸" << "🔹"
                   << "🔶" << "🔷" << "🔳" << "🔲" << "▪️" << "▫️" << "◾️" << "◽️";
     }
     
     QString getEmojiName(int index) {
         // Simplified names for the emojis
         static QStringList names = {
             "Grinning", "Beaming", "Tears", "Rolling", "Smiley", "Happy", "Sweat", "Laughing",
             "Wink", "Blushing", "Yum", "Cool", "Heart-eyes", "Kissing", "Kissing", "Kissing",
             "Kissing", "Slight", "Hugging", "Thinking", "Neutral", "Expressionless", "No-mouth", "Rolling-eyes",
             "Smirk", "Persevere", "Disappointed", "Open-mouth", "Zipper", "Hushed", "Sleepy", "Tired",
             "Sleeping", "Relieved", "Nerd", "Tongue", "Wink-tongue", "Squint-tongue", "Drool", "Unamused",
             "Downcast", "Pensive", "Confused", "Upside-down", "Money", "Astonished", "Frowning", "Slight-frown",
             "Confounded", "Disappointed", "Worried", "Angry", "Crying", "Sobbing", "Anguished", "Fearful",
             "Grimacing", "Anxious", "Scared", "Flushed", "Dizzy", "Pouting",
             "Angry", "Mask", "Sick", "Hurt", "Nauseated", "Sneezing", "Angel", "Cowboy",
             "Clown", "Lying", "Shushing", "Hand-over-mouth", "Monocle", "Exploding", "Wild", "Swearing",
             "Orange-heart", "Yellow-heart", "Green-heart", "Blue-heart", "Purple-heart", "Black-heart", "Broken-heart", "Red-heart",
             "Two-hearts", "Heart-ribbon", "Beating-heart", "Growing-heart", "Sparkling-heart", "Heart-arrow", "Heart-ribbon", "Heart-circle",
             "Peace", "Cross", "Star-crescent", "Om", "Wheel", "Star-david", "Star-of-david", "Menorah",
             "Yin-yang", "Cross", "Place-worship", "Ophiuchus", "Aries", "Taurus", "Gemini", "Cancer",
             "Leo", "Virgo", "Libra", "Scorpio", "Sagittarius", "Capricorn", "Aquarius", "Pisces",
             "ID-button", "Atom", "Accept", "Radioactive", "Biohazard", "Mobile-off", "Vibration", "Not-free",
             "Free", "Application", "Open-business", "Monthly", "Circled-star", "VS-button", "White-flower", "Bargain",
             "Secret", "Congratulations", "Passing", "Full", "Discount", "Prohibited", "A-button", "B-button",
             "AB-button", "CL-button", "O-button", "SOS", "Cross-mark", "Circle", "Stop", "No-entry",
             "Name-badge", "Prohibited", "Hundred", "Anger", "Hot-springs", "No-pedestrians", "No-littering", "No-bicycles",
             "No-water", "No-under-18", "No-phones", "No-smoking", "Exclamation", "White-exclamation", "Question", "White-question",
             "Double-exclamation", "Exclamation-question", "Dim", "Bright", "Part-alternation", "Warning", "Children-crossing", "Trident",
             "Fleur-de-lis", "Beginner", "Recycle", "Check-mark", "Green-check", "Chart-up", "Sparkle", "Green-sparkle",
             "X-mark", "Globe", "Diamond", "Circled-M", "Cyclone", "Zzz", "ATM", "WC",
             "Wheelchair", "Parking", "Empty", "Service-charge", "Passport", "Customs", "Baggage", "Baggage-claim",
             "Mens", "Womens", "Baby", "Restroom", "Litter", "Cinema", "Signal", "Japanese-here",
             "Symbols", "Information", "ABCD", "abc", "ABC", "NG-button", "OK-button", "Up-button",
             "Cool-button", "New-button", "Free-button", "Zero", "One", "Two", "Three", "Four",
             "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Numbers", "Hash-key",
             "Asterisk", "Play", "Pause", "Play-pause", "Stop", "Record", "Next", "Previous",
             "Fast-forward", "Rewind", "Up", "Down", "Left-arrow", "Up-triangle", "Down-triangle", "Right-arrow",
             "Left-arrow", "Up-arrow", "Down-arrow", "Up-right", "Down-right", "Down-left", "Up-left", "Up-down",
             "Left-right", "Right-curve", "Left-curve", "Up-curve", "Down-curve", "Shuffle", "Repeat", "Repeat-one",
             "Arrows", "Arrows", "Musical-note", "Notes", "Plus", "Minus", "Divide", "Multiply",
             "Dollar", "Currency", "Trademark", "Copyright", "Registered", "Wavy-dash", "Curly-loop", "Double-curly",
             "End-arrow", "Back-arrow", "On-arrow", "Top-arrow", "Soon-arrow", "Check", "Checkbox", "Radio-button",
             "White-circle", "Black-circle", "Red-circle", "Blue-circle", "Red-triangle-up", "Red-triangle-down", "Orange-diamond", "Blue-diamond",
             "Orange-diamond", "Blue-diamond", "White-square", "Black-square", "Black-small", "White-small", "Black-medium", "White-medium"
         };
         
         if (index >= 0 && index < names.size()) {
             return names[index];
         }
         return "Unknown";
     }
 };
 
 // ----------------
 // MAIN WINDOW
 // ----------------
 
 // Main window of the application
 class MainWindow : public QMainWindow {
     Q_OBJECT
     
 private:
     // UI elements
     QWidget* centralWidget;
     QTabWidget* tabWidget;
     
     // Login tab
     QWidget* loginTab;
     QLineEdit* serverAddressEdit;
     QLineEdit* serverPortEdit;
     QLineEdit* turnServerEdit;
     QLineEdit* turnPortEdit;
     QLineEdit* usernameEdit;
     QPushButton* connectButton;
     QLabel* statusLabel;
     
     // Contacts tab
     QWidget* contactsTab;
     QListWidget* contactsList;
     QPushButton* refreshButton;
     QPushButton* callButton;
     QCheckBox* videoCheckBox;
     QCheckBox* screenShareCheckBox;
     
     // Call tab
     QWidget* callTab;
     QLabel* callStatusLabel;
     QLabel* peerNameLabel;
     QLabel* callDurationLabel;
     QPushButton* endCallButton;
     QPushButton* acceptButton;
     QPushButton* rejectButton;
     EmojiVisualizer* emojiVisualizer;
     
     // Video display widgets
     QWidget* localVideoWidget;
     QWidget* remoteVideoWidget;
     
     // Text chat (simplified)
     QTextEdit* chatDisplay;
     QLineEdit* chatInput;
     QPushButton* sendButton;
     
     // Network handler
     NetworkHandler* networkHandler;
     
     // Timer for call duration
     QTimer* durationTimer;
     QTime callDuration;
     
 public:
     MainWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
         setWindowTitle("PX Encrypted Calling App");
         setMinimumSize(800, 600);
         
         // Create network handler
         networkHandler = new NetworkHandler(this);
         
         // Connect signals and slots
         connect(networkHandler, &NetworkHandler::registered, this, &MainWindow::onRegistered);
         connect(networkHandler, &NetworkHandler::error, this, &MainWindow::onError);
         connect(networkHandler, &NetworkHandler::userListReceived, this, &MainWindow::onUserListReceived);
         connect(networkHandler, &NetworkHandler::incomingCall, this, &MainWindow::onIncomingCall);
         connect(networkHandler, &NetworkHandler::callAccepted, this, &MainWindow::onCallAccepted);
         connect(networkHandler, &NetworkHandler::callRejected, this, &MainWindow::onCallRejected);
         connect(networkHandler, &NetworkHandler::callEnded, this, &MainWindow::onCallEnded);
         connect(networkHandler, &NetworkHandler::p2pEstablished, this, &MainWindow::onP2PEstablished);
         connect(networkHandler, &NetworkHandler::mediaReceived, this, &MainWindow::onMediaReceived);
         connect(networkHandler, &NetworkHandler::keyExchangeCompleted, this, &MainWindow::onKeyExchangeCompleted);
         
         // Create call duration timer
         durationTimer = new QTimer(this);
         connect(durationTimer, &QTimer::timeout, this, &MainWindow::updateCallDuration);
         
         // Set up UI
         setupUI();
     }
     
     ~MainWindow() {
         // Ensure clean disconnect
         networkHandler->disconnect();
     }
     
 private:
     void setupUI() {
         centralWidget = new QWidget();
         setCentralWidget(centralWidget);
         
         // Main layout
         QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
         
         // Create tab widget
         tabWidget = new QTabWidget();
         mainLayout->addWidget(tabWidget);
         
         // Create login tab
         setupLoginTab();
         
         // Create contacts tab
         setupContactsTab();
         
         // Create call tab
         setupCallTab();
         
         // Add tabs
         tabWidget->addTab(loginTab, "Login");
         tabWidget->addTab(contactsTab, "Contacts");
         tabWidget->addTab(callTab, "Active Call");
         
         // Disable tabs initially
         tabWidget->setTabEnabled(1, false);
         tabWidget->setTabEnabled(2, false);
     }
     
     void setupLoginTab() {
         loginTab = new QWidget();
         QVBoxLayout* layout = new QVBoxLayout(loginTab);
         
         QGroupBox* serverGroup = new QGroupBox("Server Settings");
         QFormLayout* serverLayout = new QFormLayout();
         
         serverAddressEdit = new QLineEdit("127.0.0.1");
         serverPortEdit = new QLineEdit(QString::number(DEFAULT_SERVER_PORT));
         turnServerEdit = new QLineEdit("127.0.0.1");
         turnPortEdit = new QLineEdit(QString::number(DEFAULT_TURN_PORT));
         
         serverLayout->addRow("Server Address:", serverAddressEdit);
         serverLayout->addRow("Server Port:", serverPortEdit);
         serverLayout->addRow("TURN Server:", turnServerEdit);
         serverLayout->addRow("TURN Port:", turnPortEdit);
         
         serverGroup->setLayout(serverLayout);
         layout->addWidget(serverGroup);
         
         QGroupBox* userGroup = new QGroupBox("User Information");
         QFormLayout* userLayout = new QFormLayout();
         
         usernameEdit = new QLineEdit();
         userLayout->addRow("Username:", usernameEdit);
         
         userGroup->setLayout(userLayout);
         layout->addWidget(userGroup);
         
         connectButton = new QPushButton("Connect");
         layout->addWidget(connectButton);
         
         statusLabel = new QLabel("Not connected");
         layout->addWidget(statusLabel);
         
         layout->addStretch();
         
         // Connect button signal
         connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
     }
     
     void setupContactsTab() {
         contactsTab = new QWidget();
         QVBoxLayout* layout = new QVBoxLayout(contactsTab);
         
         // User list
         QGroupBox* contactsGroup = new QGroupBox("Online Users");
         QVBoxLayout* contactsLayout = new QVBoxLayout();
         
         contactsList = new QListWidget();
         contactsLayout->addWidget(contactsList);
         
         refreshButton = new QPushButton("Refresh");
         contactsLayout->addWidget(refreshButton);
         
         contactsGroup->setLayout(contactsLayout);
         layout->addWidget(contactsGroup);
         
         // Call options
         QGroupBox* callGroup = new QGroupBox("Call Options");
         QVBoxLayout* callLayout = new QVBoxLayout();
         
         videoCheckBox = new QCheckBox("Video Call");
         screenShareCheckBox = new QCheckBox("Screen Sharing");
         callLayout->addWidget(videoCheckBox);
         callLayout->addWidget(screenShareCheckBox);
         
         callButton = new QPushButton("Call Selected User");
         callButton->setEnabled(false);
         callLayout->addWidget(callButton);
         
         callGroup->setLayout(callLayout);
         layout->addWidget(callGroup);
         
         // Connect signals
         connect(refreshButton, &QPushButton::clicked, this, &MainWindow::onRefreshClicked);
         connect(callButton, &QPushButton::clicked, this, &MainWindow::onCallClicked);
         connect(contactsList, &QListWidget::itemSelectionChanged, this, &MainWindow::onContactSelectionChanged);
     }
     
     void setupCallTab() {
         callTab = new QWidget();
         QVBoxLayout* layout = new QVBoxLayout(callTab);
         
         // Call info
         QGroupBox* infoGroup = new QGroupBox("Call Information");
         QGridLayout* infoLayout = new QGridLayout();
         
         callStatusLabel = new QLabel("Not in a call");
         peerNameLabel = new QLabel("No peer");
         callDurationLabel = new QLabel("00:00:00");
         
         infoLayout->addWidget(new QLabel("Status:"), 0, 0);
         infoLayout->addWidget(callStatusLabel, 0, 1);
         infoLayout->addWidget(new QLabel("Peer:"), 1, 0);
         infoLayout->addWidget(peerNameLabel, 1, 1);
         infoLayout->addWidget(new QLabel("Duration:"), 2, 0);
         infoLayout->addWidget(callDurationLabel, 2, 1);
         
         infoGroup->setLayout(infoLayout);
         layout->addWidget(infoGroup);
         
         // Key verification
         QGroupBox* verifyGroup = new QGroupBox("Security Verification");
         QVBoxLayout* verifyLayout = new QVBoxLayout();
         
         QLabel* verifyLabel = new QLabel("Compare these emojis with your peer to verify the connection is secure:");
         verifyLayout->addWidget(verifyLabel);
         
         emojiVisualizer = new EmojiVisualizer();
         verifyLayout->addWidget(emojiVisualizer);
         
         verifyGroup->setLayout(verifyLayout);
         layout->addWidget(verifyGroup);
         
         // Video displays
         QHBoxLayout* videoLayout = new QHBoxLayout();
         
         localVideoWidget = new QWidget();
         localVideoWidget->setMinimumSize(320, 240);
         localVideoWidget->setAutoFillBackground(true);
         QPalette pal = localVideoWidget->palette();
         pal.setColor(QPalette::Window, Qt::black);
         localVideoWidget->setPalette(pal);
         
         remoteVideoWidget = new QWidget();
         remoteVideoWidget->setMinimumSize(320, 240);
         remoteVideoWidget->setAutoFillBackground(true);
         remoteVideoWidget->setPalette(pal);
         
         videoLayout->addWidget(localVideoWidget);
         videoLayout->addWidget(remoteVideoWidget);
         
         layout->addLayout(videoLayout);
         
         // Call control buttons
         QHBoxLayout* buttonLayout = new QHBoxLayout();
         
         acceptButton = new QPushButton("Accept");
         rejectButton = new QPushButton("Reject");
         endCallButton = new QPushButton("End Call");
         
         acceptButton->setVisible(false);
         rejectButton->setVisible(false);
         
         buttonLayout->addWidget(acceptButton);
         buttonLayout->addWidget(rejectButton);
         buttonLayout->addWidget(endCallButton);
         
         layout->addLayout(buttonLayout);
         
         // Text chat
         QGroupBox* chatGroup = new QGroupBox("Text Chat");
         QVBoxLayout* chatLayout = new QVBoxLayout();
         
         chatDisplay = new QTextEdit();
         chatDisplay->setReadOnly(true);
         chatLayout->addWidget(chatDisplay);
         
         QHBoxLayout* chatInputLayout = new QHBoxLayout();
         chatInput = new QLineEdit();
         sendButton = new QPushButton("Send");
         
         chatInputLayout->addWidget(chatInput);
         chatInputLayout->addWidget(sendButton);
         
         chatLayout->addLayout(chatInputLayout);
         chatGroup->setLayout(chatLayout);
         layout->addWidget(chatGroup);
         
         // Connect signals
         connect(acceptButton, &QPushButton::clicked, this, &MainWindow::onAcceptClicked);
         connect(rejectButton, &QPushButton::clicked, this, &MainWindow::onRejectClicked);
         connect(endCallButton, &QPushButton::clicked, this, &MainWindow::onEndCallClicked);
         connect(sendButton, &QPushButton::clicked, this, &MainWindow::onSendClicked);
         connect(chatInput, &QLineEdit::returnPressed, this, &MainWindow::onSendClicked);
     }
     
     // Slot for connect button
     void onConnectClicked() {
         QString serverAddress = serverAddressEdit->text();
         int serverPort = serverPortEdit->text().toInt();
         QString turnServer = turnServerEdit->text();
         int turnPort = turnPortEdit->text().toInt();
         QString username = usernameEdit->text();
         
         if (username.isEmpty()) {
             QMessageBox::warning(this, "Error", "Please enter a username");
             return;
         }
         
         statusLabel->setText("Connecting...");
         connectButton->setEnabled(false);
         
         // Connect to server
         if (!networkHandler->connect(serverAddress.toStdString(), serverPort, 
                                      turnServer.toStdString(), turnPort)) {
             statusLabel->setText("Connection failed");
             connectButton->setEnabled(true);
             return;
         }
         
         // Register with server
         if (!networkHandler->registerWithServer(username.toStdString())) {
             statusLabel->setText("Registration failed");
             connectButton->setEnabled(true);
             return;
         }
     }
     
     // Slot for refresh button
     void onRefreshClicked() {
         networkHandler->requestUserList();
     }
     
     // Slot for call button
     void onCallClicked() {
         QListWidgetItem* item = contactsList->currentItem();
         if (!item) {
             return;
         }
         
         // Get user ID from the item data
         uint32_t userId = item->data(Qt::UserRole).toUInt();
         
         bool video = videoCheckBox->isChecked();
         bool screenShare = screenShareCheckBox->isChecked();
         
         // Start call
         if (networkHandler->startCall(userId, video, screenShare)) {
             // Switch to call tab
             tabWidget->setCurrentIndex(2);
             
             // Update UI
             callStatusLabel->setText("Calling...");
             peerNameLabel->setText(item->text());
             
             // Show/hide buttons
             acceptButton->setVisible(false);
             rejectButton->setVisible(false);
             endCallButton->setVisible(true);
         }
     }
     
     // Slot for contact selection
     void onContactSelectionChanged() {
         callButton->setEnabled(!contactsList->selectedItems().isEmpty());
     }
     
     // Slot for accept button
     void onAcceptClicked() {
         bool video = videoCheckBox->isChecked();
         bool screenShare = screenShareCheckBox->isChecked();
         
         if (networkHandler->acceptCall(video, screenShare)) {
             // Update UI
             callStatusLabel->setText("Connecting...");
             
             // Show/hide buttons
             acceptButton->setVisible(false);
             rejectButton->setVisible(false);
             endCallButton->setVisible(true);
         }
     }
     
     // Slot for reject button
     void onRejectClicked() {
         if (networkHandler->rejectCall()) {
             // Switch back to contacts tab
             tabWidget->setCurrentIndex(1);
             
             // Update UI
             callStatusLabel->setText("Not in a call");
             peerNameLabel->setText("No peer");
             callDurationLabel->setText("00:00:00");
             
             // Clear emoji visualizer
             emojiVisualizer->setEmojiIndices({});
         }
     }
     
     // Slot for end call button
     void onEndCallClicked() {
         if (networkHandler->endCall()) {
             // Switch back to contacts tab
             tabWidget->setCurrentIndex(1);
             
             // Update UI
             callStatusLabel->setText("Not in a call");
             peerNameLabel->setText("No peer");
             callDurationLabel->setText("00:00:00");
             
             // Stop duration timer
             durationTimer->stop();
             
             // Clear emoji visualizer
             emojiVisualizer->setEmojiIndices({});
         }
     }
     
     // Slot for send button
     void onSendClicked() {
         QString message = chatInput->text();
         if (message.isEmpty()) {
             return;
         }
         
         // Convert message to bytes
         QByteArray textData = message.toUtf8();
         std::vector<uint8_t> data(textData.begin(), textData.end());
         
         // Send message
         if (networkHandler->sendMediaData(MediaType::AUDIO, data)) { // Using AUDIO type for text messages for simplicity
             // Add message to chat display
             chatDisplay->append("<b>You:</b> " + message);
             
             // Clear input
             chatInput->clear();
         }
     }
     
     // Slot for registered event
     void onRegistered(uint32_t clientId) {
         statusLabel->setText("Connected and registered with ID: " + QString::number(clientId));
         
         // Enable contacts tab
         tabWidget->setTabEnabled(1, true);
         
         // Switch to contacts tab
         tabWidget->setCurrentIndex(1);
         
         // Request user list
         networkHandler->requestUserList();
     }
     
     // Slot for error event
     void onError(const QString& message) {
         QMessageBox::warning(this, "Error", message);
     }
     
     // Slot for user list received event
     void onUserListReceived() {
         contactsList->clear();
         
         auto users = networkHandler->getUsers();
         for (const auto& user_pair : users) {
             QListWidgetItem* item = new QListWidgetItem(QString::fromStdString(user_pair.second.username));
             item->setData(Qt::UserRole, QVariant(user_pair.first));
             contactsList->addItem(item);
         }
     }
     
     // Slot for incoming call event
     void onIncomingCall(uint32_t callerId, const QString& callerName) {
         // Switch to call tab
         tabWidget->setCurrentIndex(2);
         tabWidget->setTabEnabled(2, true);
         
         // Update UI
         callStatusLabel->setText("Incoming call...");
         peerNameLabel->setText(callerName);
         
         // Show accept/reject buttons
         acceptButton->setVisible(true);
         rejectButton->setVisible(true);
         endCallButton->setVisible(false);
         
         // Play ring sound (would be implemented in real app)
         
         // Show notification dialog
         QMessageBox::information(this, "Incoming Call", "Incoming call from " + callerName);
     }
     
     // Slot for call accepted event
     void onCallAccepted() {
         // Update UI
         callStatusLabel->setText("Call accepted, establishing secure connection...");
     }
     
     // Slot for call rejected event
     void onCallRejected() {
         // Switch back to contacts tab
         tabWidget->setCurrentIndex(1);
         
         // Update UI
         callStatusLabel->setText("Call rejected");
         
         // Show notification
         QMessageBox::information(this, "Call Rejected", "Your call was rejected");
     }
     
     // Slot for call ended event
     void onCallEnded() {
         // Switch back to contacts tab
         tabWidget->setCurrentIndex(1);
         
         // Update UI
         callStatusLabel->setText("Call ended");
         peerNameLabel->setText("No peer");
         callDurationLabel->setText("00:00:00");
         
         // Stop duration timer
         durationTimer->stop();
         
         // Clear emoji visualizer
         emojiVisualizer->setEmojiIndices({});
         
         // Clear chat
         chatDisplay->clear();
         
         // Show notification
         QMessageBox::information(this, "Call Ended", "The call has ended");
     }
     
     // Slot for P2P established event
     void onP2PEstablished() {
         // Update UI
         callStatusLabel->setText("Call connected");
         
         // Start duration timer
         callDuration = QTime(0, 0, 0);
         durationTimer->start(1000);
         
         // Show key verification
         emojiVisualizer->setEmojiIndices(networkHandler->getEmojiVerification());
     }
     
     // Slot for media received event
     void onMediaReceived(int type, const QByteArray& data) {
         MediaType mediaType = static_cast<MediaType>(type);
         
         if (mediaType == MediaType::AUDIO) {
             // For simplicity, treat audio packets as text messages in this demo
             QString message = QString::fromUtf8(data);
             chatDisplay->append("<b>Peer:</b> " + message);
         }
         else if (mediaType == MediaType::VIDEO) {
             // Process video data (would be implemented in real app)
         }
         else if (mediaType == MediaType::SCREEN) {
             // Process screen sharing data (would be implemented in real app)
         }
     }
     
     // Slot for key exchange completed event
     void onKeyExchangeCompleted() {
         // Update emoji visualization
         emojiVisualizer->setEmojiIndices(networkHandler->getEmojiVerification());
     }
     
     // Slot for updating call duration
     void updateCallDuration() {
         callDuration = callDuration.addSecs(1);
         callDurationLabel->setText(callDuration.toString("hh:mm:ss"));
     }
 };
 
 // ----------------
 // MAIN FUNCTION
 // ----------------
 
 int main(int argc, char** argv) {
     QApplication app(argc, argv);
     
     // Apply style
     QApplication::setStyle(QStyleFactory::create("Fusion"));
     
     // Create main window
     MainWindow mainWindow;
     mainWindow.show();
     
     return app.exec();
 }
 
 // Include generated MOC (Meta-Object Compiler) code
 #include "client.moc"
 
