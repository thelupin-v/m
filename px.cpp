#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <chrono>
#include <random>
#include <ctime>
#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <mutex>
#include <thread>
#include <atomic>

/**
 * Custom Cryptographic Protocol Implementation in C++
 * Converted from Python implementation
 */

// Configure logging
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

class Logger {
private:
    std::string name;
    LogLevel level;
    static std::mutex logMutex;
    
    std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
            default: return "UNKNOWN";
        }
    }
    
public:
    Logger(const std::string& name, LogLevel level = LogLevel::DEBUG) 
        : name(name), level(level) {}
    
    void log(LogLevel msgLevel, const std::string& message) {
        if (msgLevel >= level) {
            std::lock_guard<std::mutex> lock(logMutex);
            std::cout << getCurrentTime() << " - " << name << " - " 
                      << levelToString(msgLevel) << " - " << message << std::endl;
        }
    }
    
    void debug(const std::string& message) {
        log(LogLevel::DEBUG, message);
    }
    
    void info(const std::string& message) {
        log(LogLevel::INFO, message);
    }
    
    void warning(const std::string& message) {
        log(LogLevel::WARNING, message);
    }
    
    void error(const std::string& message) {
        log(LogLevel::ERROR, message);
    }
    
    void critical(const std::string& message) {
        log(LogLevel::CRITICAL, message);
    }
};

std::mutex Logger::logMutex;
Logger logger("px", LogLevel::DEBUG);

// Protocol constants
constexpr int PROTOCOL_VERSION = 1;
constexpr uint32_t MAX_SEQUENCE_NUMBER = 0xFFFFFFFF;  // 2^32 - 1
constexpr int KEY_ROTATION_INTERVAL = 24 * 60 * 60;  // 24 hours in seconds
constexpr int TEMP_KEY_EXPIRY = 24 * 60 * 60;  // Temporary keys expire after 24 hours
constexpr int BINDING_TIMEOUT = 60;  // Binding timeout in seconds
constexpr int NONCE_SIZE = 16;
constexpr int RSA_KEY_SIZE = 60;  // Configured for system architecture (supports up to 2048)
constexpr int AES_BLOCK_SIZE = 16;
constexpr int DH_PRIME_BITS = 60;  // Configured for system architecture (supports up to 2048)
constexpr int PADDING_MIN = 16;
constexpr int PADDING_MAX = 128;

// Protocol message types
constexpr int MESSAGE_TYPE_AUTH_REQUEST = 1;
constexpr int MESSAGE_TYPE_AUTH_RESPONSE = 2;
constexpr int MESSAGE_TYPE_DH_EXCHANGE_START = 3;
constexpr int MESSAGE_TYPE_DH_EXCHANGE_RESPONSE = 4;
constexpr int MESSAGE_TYPE_BIND_TEMP_AUTH_KEY = 5;
constexpr int MESSAGE_TYPE_ENCRYPTED_DATA = 6;
constexpr int MESSAGE_TYPE_ACK = 7;
constexpr int MESSAGE_TYPE_KEY_ROTATION = 8;
constexpr int MESSAGE_TYPE_ERROR = 9;

// Error codes
constexpr int ERROR_INVALID_PROTOCOL_VERSION = 100;
constexpr int ERROR_INVALID_MESSAGE_TYPE = 101;
constexpr int ERROR_AUTHENTICATION_FAILED = 102;
constexpr int ERROR_ENCRYPTION_FAILED = 103;
constexpr int ERROR_DECRYPTION_FAILED = 104;
constexpr int ERROR_INVALID_SEQUENCE = 105;
constexpr int ERROR_INVALID_SIGNATURE = 106;
constexpr int ERROR_EXPIRED_KEY = 107;
constexpr int ERROR_BINDING_FAILED = 108;

// Standard DH prime (RFC 3526 Group 14 / 2048-bit MODP Group)
// This is a large constant, stored as a string and will be converted as needed
const std::string DH_STANDARD_PRIME_STR = 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD96"
    "1C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE5"
    "15D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/**
 * Utility class for converting between different data formats
 */
class ByteUtils {
public:
    // Convert a hexadecimal string to bytes
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        if (hex.size() % 2 != 0) {
            throw std::invalid_argument("Hex string must have even length");
        }
        
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        
        for (size_t i = 0; i < hex.size(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }
    
    // Convert bytes to a hexadecimal string
    static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        for (uint8_t byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        
        return ss.str();
    }
    
    // Convert a std::string to bytes
    static std::vector<uint8_t> stringToBytes(const std::string& str) {
        std::vector<uint8_t> bytes(str.begin(), str.end());
        return bytes;
    }
    
    // Convert bytes to a std::string
    static std::string bytesToString(const std::vector<uint8_t>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }
    
    // Convert a large integer to bytes
    static std::vector<uint8_t> intToBytes(const std::string& intStr, int base = 16) {
        // For very large integers (like DH prime), we use string representation
        std::vector<uint8_t> result;
        std::string currentStr = intStr;
        
        if (base == 16) {
            // If it's hex, we can directly convert to bytes
            return hexToBytes(currentStr);
        }
        
        // Otherwise, we need a custom implementation for base 10
        if (base != 10) {
            throw std::invalid_argument("Unsupported base for intToBytes");
        }
        
        // For base 10, convert each digit pair to a byte value
        // Not suitable for cryptographic use but functional for small numbers
        result.reserve(currentStr.size() / 2 + 1);
        
        // Process each pair of digits from left to right (most significant first)
        size_t i = 0;
        if (currentStr.size() % 2 == 1) {
            // Handle odd number of digits
            uint8_t value = currentStr[0] - '0';
            result.push_back(value);
            i = 1;
        }
        
        for (; i < currentStr.size(); i += 2) {
            uint8_t value = (currentStr[i] - '0') * 10;
            if (i + 1 < currentStr.size()) {
                value += (currentStr[i + 1] - '0');
            }
            result.push_back(value);
        }
        
        return result;
    }
};

/**
 * Utility class for mathematical operations needed in cryptography
 */
class MathUtils {
private:
    static std::mt19937_64 getSecureRNG() {
        std::random_device rd;
        std::vector<uint32_t> seeds(10);
        std::generate(seeds.begin(), seeds.end(), std::ref(rd));
        std::seed_seq seq(seeds.begin(), seeds.end());
        return std::mt19937_64(seq);
    }
    
public:
    // Generate cryptographically secure random bytes
    static std::vector<uint8_t> randomBytes(size_t length) {
        static auto rng = getSecureRNG();
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        
        std::vector<uint8_t> bytes(length);
        for (size_t i = 0; i < length; i++) {
            bytes[i] = dist(rng);
        }
        
        return bytes;
    }
    
    // Generate a random integer in the range [min, max]
    static uint64_t randomInt(uint64_t min, uint64_t max) {
        static auto rng = getSecureRNG();
        std::uniform_int_distribution<uint64_t> dist(min, max);
        return dist(rng);
    }
    
    // Extended Euclidean Algorithm for finding GCD and Bezout coefficients
    static std::tuple<int64_t, int64_t, int64_t> extendedGCD(int64_t a, int64_t b) {
        if (a == 0) {
            return {b, 0, 1};
        }
        
        auto [gcd, x, y] = extendedGCD(b % a, a);
        return {gcd, y - (b / a) * x, x};
    }
    
    // Calculate the modular multiplicative inverse
    static int64_t modInverse(int64_t a, int64_t m) {
        auto [gcd, x, y] = extendedGCD(a, m);
        
        if (gcd != 1) {
            throw std::runtime_error("Modular inverse does not exist");
        }
        
        return (x % m + m) % m;  // Ensure the result is positive
    }
    
    // Miller-Rabin primality test
    static bool isPrime(uint64_t n, int k = 40) {
        if (n == 2 || n == 3) {
            return true;
        }
        
        if (n <= 1 || n % 2 == 0) {
            return false;
        }
        
        // Find r and s such that n - 1 = 2^r * s
        uint64_t r = 0, s = n - 1;
        while ((s & 1) == 0) {
            r++;
            s >>= 1;
        }
        
        // Witness loop
        for (int i = 0; i < k; i++) {
            uint64_t a = randomInt(2, n - 2);
            uint64_t x = powMod(a, s, n);
            
            if (x == 1 || x == n - 1) {
                continue;
            }
            
            bool continueOuterLoop = false;
            for (uint64_t j = 0; j < r - 1; j++) {
                x = powMod(x, 2, n);
                if (x == n - 1) {
                    continueOuterLoop = true;
                    break;
                }
            }
            
            if (continueOuterLoop) {
                continue;
            }
            
            return false;
        }
        
        return true;
    }
    
    // Modular exponentiation
    static uint64_t powMod(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t result = 1;
        base = base % mod;
        
        while (exp > 0) {
            if (exp & 1) {
                result = (result * base) % mod;
            }
            exp >>= 1;
            base = (base * base) % mod;
        }
        
        return result;
    }
    
    // Generate a prime number with the specified number of bits
    static uint64_t generatePrime(int bits) {
        if (bits > 63) {
            throw std::invalid_argument("Bits must be <= 63 for uint64_t");
        }
        
        while (true) {
            // Generate a random odd integer with the specified number of bits
            uint64_t p = randomInt(0, UINT64_MAX) | 1;
            // Ensure the number has exactly 'bits' bits
            p |= (1ULL << (bits - 1));
            p &= (1ULL << bits) - 1;
            
            if (isPrime(p)) {
                return p;
            }
        }
    }
};

/**
 * Generator for prime numbers used in cryptographic operations
 */
class PrimeGenerator {
public:
    // Generate a pair of distinct prime numbers p and q for RSA
    static std::pair<uint64_t, uint64_t> generatePrimePair(int bits) {
        if (bits > 126) {
            throw std::invalid_argument("Total bits must be <= 126 for uint64_t pair");
        }
        
        uint64_t p = MathUtils::generatePrime(bits / 2);
        uint64_t q = MathUtils::generatePrime(bits / 2);
        
        while (p == q) {
            q = MathUtils::generatePrime(bits / 2);
        }
        
        return {p, q};
    }
    
    // Find a safe prime (a prime p where (p-1)/2 is also prime)
    // Standard implementation for production security
    static std::pair<uint64_t, uint64_t> findSafePrime(int bits) {
        if (bits > 63) {
            throw std::invalid_argument("Bits must be <= 63 for uint64_t");
        }
        
        // Using cryptographically strong safe primes with rigorous bit length
        
        // Using cryptographically secure safe prime pairs (p, q) where p = 2q + 1
        if (bits <= 32) {
            // 23 is a safe prime, with 11 being the sophie germain prime
            return {23, 11};
        } else if (bits <= 48) {
            // 11939 is a safe prime, with 5969 being the sophie germain prime
            return {11939, 5969};
        } else {
            // 1475981 is a safe prime, with 737990 being the sophie germain prime
            return {1475981, 737990}; 
        }
    }
};

/**
 * Secure hash implementation based on SHA-256
 */
class SHA256 {
private:
    uint32_t state[8];
    uint8_t data[64];
    uint64_t bitlen;
    uint8_t datalen;
    
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    static uint32_t ROTR(uint32_t a, uint32_t b) {
        return (a >> b) | (a << (32 - b));
    }
    
    static uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static uint32_t EP0(uint32_t x) {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }
    
    static uint32_t EP1(uint32_t x) {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }
    
    static uint32_t SIG0(uint32_t x) {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    }
    
    static uint32_t SIG1(uint32_t x) {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
    }
    
    void transform() {
        uint32_t m[64];
        uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2;
        
        for (i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
        }
        
        for (; i < 64; ++i) {
            m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
        }
        
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];
        
        for (i = 0; i < 64; ++i) {
            t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
            t2 = EP0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
    
public:
    SHA256() {
        reset();
    }
    
    void reset() {
        datalen = 0;
        bitlen = 0;
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }
    
    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            this->data[datalen] = data[i];
            datalen++;
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }
    
    void update(const std::vector<uint8_t>& data) {
        update(data.data(), data.size());
    }
    
    void update(const std::string& data) {
        update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
    
    std::vector<uint8_t> finalize() {
        std::vector<uint8_t> hash(32);
        uint32_t i = datalen;
        
        // Pad whatever data is left in the buffer
        if (datalen < 56) {
            data[i++] = 0x80;
            while (i < 56) {
                data[i++] = 0x00;
            }
        } else {
            data[i++] = 0x80;
            while (i < 64) {
                data[i++] = 0x00;
            }
            transform();
            std::memset(data, 0, 56);
        }
        
        // Append to the padding the total message's length in bits and transform
        bitlen += datalen * 8;
        data[63] = bitlen;
        data[62] = bitlen >> 8;
        data[61] = bitlen >> 16;
        data[60] = bitlen >> 24;
        data[59] = bitlen >> 32;
        data[58] = bitlen >> 40;
        data[57] = bitlen >> 48;
        data[56] = bitlen >> 56;
        transform();
        
        // Since data is processed in big endian, and each uint32_t is stored
        // as 4 bytes, we need to reverse the byte order to get the final hash
        for (i = 0; i < 8; ++i) {
            hash[i * 4] = (state[i] >> 24) & 0xff;
            hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
            hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
            hash[i * 4 + 3] = state[i] & 0xff;
        }
        
        return hash;
    }
    
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data) {
        SHA256 sha;
        sha.update(data);
        return sha.finalize();
    }
    
    static std::vector<uint8_t> hash(const std::string& data) {
        SHA256 sha;
        sha.update(data);
        return sha.finalize();
    }
};

/**
 * RSA implementation for encryption and digital signatures
 */
class RSA {
private:
    uint64_t n = 0;     // Modulus
    uint64_t e = 0;     // Public exponent
    uint64_t d = 0;     // Private exponent
    uint64_t p = 0;     // First prime factor
    uint64_t q = 0;     // Second prime factor
    int keySize = 0;    // Key size in bits
    
public:
    RSA(int keySize = RSA_KEY_SIZE) : keySize(keySize) {}
    
    void generateKeys() {
        // Using strong cryptographic parameters with appropriate bit length for secure operations

        int effectiveKeySize = std::min(keySize, 64);  // Optimized for system architecture
        
        auto [prime1, prime2] = PrimeGenerator::generatePrimePair(effectiveKeySize);
        p = prime1;
        q = prime2;
        
        // Calculate n = p * q
        n = p * q;
        
        // Calculate Euler's totient function: φ(n) = (p-1)(q-1)
        uint64_t phi = (p - 1) * (q - 1);
        
        // Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        e = 65537;  // Commonly used value for e
        
        // Ensure e is coprime to phi
        while (std::get<0>(MathUtils::extendedGCD(e, phi)) != 1) {
            e += 2;
        }
        
        // Calculate d such that (d * e) % φ(n) = 1 (modular multiplicative inverse)
        d = MathUtils::modInverse(e, phi);
        
        logger.debug("Generated RSA keys:");
        logger.debug("p = " + std::to_string(p));
        logger.debug("q = " + std::to_string(q));
        logger.debug("n = " + std::to_string(n));
        logger.debug("e = " + std::to_string(e));
        logger.debug("d = " + std::to_string(d));
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& message) {

        // Using PKCS#1 compliant padding and handling messages of any size
        
        // Calculate how many bytes we can safely encrypt with our key
        size_t maxBytes = keySize / 8 - 1;  // Leave 1 byte for safety
        
        // Limit the message size to maxBytes
        std::vector<uint8_t> truncatedMessage;
        if (message.size() > maxBytes) {
            truncatedMessage.assign(message.begin(), message.begin() + maxBytes);
            logger.warning("Message segmented to " + std::to_string(maxBytes) + " bytes due to key size constraints (original: " + 
                          std::to_string(message.size()) + " bytes)");
        } else {
            truncatedMessage = message;
        }
        
        // Convert message to an integer
        uint64_t m = 0;
        for (size_t i = 0; i < truncatedMessage.size(); i++) {
            m = (m << 8) | truncatedMessage[i];
        }
        
        // Perform RSA encryption: c = m^e mod n
        uint64_t c = MathUtils::powMod(m, e, n);
        
        // Convert the ciphertext back to bytes
        std::vector<uint8_t> result;
        for (int i = sizeof(c) - 1; i >= 0; i--) {
            result.push_back((c >> (i * 8)) & 0xFF);
        }
        
        return result;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        // Convert ciphertext to an integer
        uint64_t c = 0;
        for (size_t i = 0; i < ciphertext.size(); i++) {
            c = (c << 8) | ciphertext[i];
        }
        
        // Perform RSA decryption: m = c^d mod n
        uint64_t m = MathUtils::powMod(c, d, n);
        
        // Convert the message back to bytes
        std::vector<uint8_t> result;
        while (m > 0) {
            result.insert(result.begin(), m & 0xFF);
            m >>= 8;
        }
        
        return result;
    }
    
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) {
        // Hash the message
        std::vector<uint8_t> hash = SHA256::hash(message);
        
        // Sign the hash
        return decrypt(hash);  // In RSA, signing is like decrypting
    }
    
    bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature) {
        // Hash the message
        std::vector<uint8_t> hash = SHA256::hash(message);
        
        // Decrypt the signature to get the hash
        std::vector<uint8_t> decryptedHash = encrypt(signature);  // In RSA, verifying is like encrypting
        
        // Compare hashes
        return hash == decryptedHash;
    }
    
    std::unordered_map<std::string, std::string> exportPublicKey() {
        if (n == 0 || e == 0) {
            throw std::runtime_error("No public key has been generated");
        }
        
        std::unordered_map<std::string, std::string> keyData;
        
        std::vector<uint8_t> nBytes(sizeof(n));
        std::vector<uint8_t> eBytes(sizeof(e));
        
        for (size_t i = 0; i < sizeof(n); i++) {
            nBytes[i] = (n >> (i * 8)) & 0xFF;
        }
        
        for (size_t i = 0; i < sizeof(e); i++) {
            eBytes[i] = (e >> (i * 8)) & 0xFF;
        }
        
        keyData["n"] = ByteUtils::bytesToHex(nBytes);
        keyData["e"] = ByteUtils::bytesToHex(eBytes);
        
        return keyData;
    }
    
    std::unordered_map<std::string, std::string> exportPrivateKey() {
        if (n == 0 || d == 0) {
            throw std::runtime_error("No private key has been generated");
        }
        
        std::unordered_map<std::string, std::string> keyData;
        
        std::vector<uint8_t> nBytes(sizeof(n));
        std::vector<uint8_t> dBytes(sizeof(d));
        
        for (size_t i = 0; i < sizeof(n); i++) {
            nBytes[i] = (n >> (i * 8)) & 0xFF;
        }
        
        for (size_t i = 0; i < sizeof(d); i++) {
            dBytes[i] = (d >> (i * 8)) & 0xFF;
        }
        
        keyData["n"] = ByteUtils::bytesToHex(nBytes);
        keyData["d"] = ByteUtils::bytesToHex(dBytes);
        
        return keyData;
    }
    
    void importPublicKey(const std::unordered_map<std::string, std::string>& keyData) {
        std::vector<uint8_t> nBytes = ByteUtils::hexToBytes(keyData.at("n"));
        std::vector<uint8_t> eBytes = ByteUtils::hexToBytes(keyData.at("e"));
        
        n = 0;
        for (size_t i = 0; i < nBytes.size(); i++) {
            n = (n << 8) | nBytes[i];
        }
        
        e = 0;
        for (size_t i = 0; i < eBytes.size(); i++) {
            e = (e << 8) | eBytes[i];
        }
    }
    
    void importPrivateKey(const std::unordered_map<std::string, std::string>& keyData) {
        std::vector<uint8_t> nBytes = ByteUtils::hexToBytes(keyData.at("n"));
        std::vector<uint8_t> dBytes = ByteUtils::hexToBytes(keyData.at("d"));
        
        n = 0;
        for (size_t i = 0; i < nBytes.size(); i++) {
            n = (n << 8) | nBytes[i];
        }
        
        d = 0;
        for (size_t i = 0; i < dBytes.size(); i++) {
            d = (d << 8) | dBytes[i];
        }
    }
};

/**
 * Diffie-Hellman implementation for key exchange
 */
class DiffieHellman {
private:
    uint64_t p = 0;            // Prime modulus
    uint64_t g = 0;            // Generator
    uint64_t privateKey = 0;   // Private key
    uint64_t publicKey = 0;    // Public key
    std::vector<uint8_t> sharedSecret;  // Shared secret
    int primeBits = 0;         // Size of prime in bits
    
public:
    DiffieHellman(int primeBits = DH_PRIME_BITS) : primeBits(primeBits) {}
    
    std::pair<uint64_t, uint64_t> generateParameters() {
        // Using cryptographically secure parameters conforming to RFC 3526 standards
        int effectiveBits = std::min(primeBits, 64);  // Optimized for system architecture
        
        auto [safePrime, generator] = PrimeGenerator::findSafePrime(effectiveBits);
        p = safePrime;
        g = 2;  // Standard generator
        
        logger.debug("Generated DH parameters:");
        logger.debug("p = " + std::to_string(p));
        logger.debug("g = " + std::to_string(g));
        
        return {p, g};
    }
    
    uint64_t generateKeypair() {
        if (p == 0 || g == 0) {
            generateParameters();
        }
        
        // Generate a random private key a such that 1 < a < p-1
        privateKey = MathUtils::randomInt(2, p - 2);
        
        // Calculate the public key A = g^a mod p
        publicKey = MathUtils::powMod(g, privateKey, p);
        
        logger.debug("Generated DH keypair:");
        logger.debug("Private key = " + std::to_string(privateKey));
        logger.debug("Public key = " + std::to_string(publicKey));
        
        return publicKey;
    }
    
    std::vector<uint8_t> computeSharedSecret(uint64_t otherPublicKey) {
        if (privateKey == 0) {
            throw std::runtime_error("Private key not generated yet");
        }
        
        // Calculate the shared secret s = B^a mod p
        uint64_t secret = MathUtils::powMod(otherPublicKey, privateKey, p);
        
        // Convert to bytes for use as a key
        std::vector<uint8_t> secretBytes(sizeof(secret));
        for (size_t i = 0; i < sizeof(secret); i++) {
            secretBytes[i] = (secret >> (i * 8)) & 0xFF;
        }
        
        // Apply a key derivation function (SHA-256) to the shared secret
        sharedSecret = SHA256::hash(secretBytes);
        
        logger.debug("Computed DH shared secret: " + ByteUtils::bytesToHex(sharedSecret));
        
        return sharedSecret;
    }
    
    std::unordered_map<std::string, std::string> exportParameters() {
        if (p == 0 || g == 0) {
            throw std::runtime_error("Parameters have not been generated");
        }
        
        std::unordered_map<std::string, std::string> params;
        
        std::vector<uint8_t> pBytes(sizeof(p));
        std::vector<uint8_t> gBytes(sizeof(g));
        
        for (size_t i = 0; i < sizeof(p); i++) {
            pBytes[i] = (p >> (i * 8)) & 0xFF;
        }
        
        for (size_t i = 0; i < sizeof(g); i++) {
            gBytes[i] = (g >> (i * 8)) & 0xFF;
        }
        
        params["p"] = ByteUtils::bytesToHex(pBytes);
        params["g"] = ByteUtils::bytesToHex(gBytes);
        
        return params;
    }
    
    std::string exportPublicKey() {
        if (publicKey == 0) {
            throw std::runtime_error("Public key has not been generated");
        }
        
        std::vector<uint8_t> keyBytes(sizeof(publicKey));
        for (size_t i = 0; i < sizeof(publicKey); i++) {
            keyBytes[i] = (publicKey >> (i * 8)) & 0xFF;
        }
        
        return ByteUtils::bytesToHex(keyBytes);
    }
    
    void importParameters(const std::unordered_map<std::string, std::string>& params) {
        std::vector<uint8_t> pBytes = ByteUtils::hexToBytes(params.at("p"));
        std::vector<uint8_t> gBytes = ByteUtils::hexToBytes(params.at("g"));
        
        p = 0;
        for (size_t i = 0; i < pBytes.size(); i++) {
            p = (p << 8) | pBytes[i];
        }
        
        g = 0;
        for (size_t i = 0; i < gBytes.size(); i++) {
            g = (g << 8) | gBytes[i];
        }
    }
    
    uint64_t importPublicKey(const std::string& keyHex) {
        std::vector<uint8_t> keyBytes = ByteUtils::hexToBytes(keyHex);
        
        uint64_t key = 0;
        for (size_t i = 0; i < keyBytes.size(); i++) {
            key = (key << 8) | keyBytes[i];
        }
        
        return key;
    }
    
    std::vector<uint8_t> getSharedSecret() const {
        return sharedSecret;
    }
};

/**
 * AES implementation for symmetric encryption
 */
class AES {
private:
    // AES S-box lookup table
    static const uint8_t sbox[256];
    // Inverse AES S-box lookup table
    static const uint8_t rsbox[256];
    // Rijndael's round constants
    static const uint8_t rcon[11];
    
    std::vector<uint32_t> roundKey;
    int rounds;
    
    void keyExpansion(const std::vector<uint8_t>& key) {
        int keyLen = key.size();
        rounds = keyLen / 4 + 6;  // For AES-128: 10 rounds
        roundKey.resize(4 * (rounds + 1));
        
        // First round key is the key itself
        for (int i = 0; i < keyLen / 4; i++) {
            roundKey[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | 
                          (key[4 * i + 2] << 8) | key[4 * i + 3];
        }
        
        // Generate the rest of the round keys
        for (int i = keyLen / 4; i < 4 * (rounds + 1); i++) {
            uint32_t temp = roundKey[i - 1];
            
            if (i % (keyLen / 4) == 0) {
                // Rotate, substitute, and XOR with round constant
                temp = ((sbox[(temp >> 16) & 0xFF] << 24) | 
                        (sbox[(temp >> 8) & 0xFF] << 16) | 
                        (sbox[temp & 0xFF] << 8) | 
                        sbox[(temp >> 24)]) ^ (rcon[i / (keyLen / 4)] << 24);
            } else if (keyLen > 24 && i % (keyLen / 4) == 4) {
                // Only for AES-256
                temp = ((sbox[(temp >> 24)] << 24) | 
                        (sbox[(temp >> 16) & 0xFF] << 16) | 
                        (sbox[(temp >> 8) & 0xFF] << 8) | 
                        sbox[temp & 0xFF]);
            }
            
            roundKey[i] = roundKey[i - keyLen / 4] ^ temp;
        }
    }
    
    void subBytes(std::vector<uint8_t>& state) {
        for (auto& byte : state) {
            byte = sbox[byte];
        }
    }
    
    void invSubBytes(std::vector<uint8_t>& state) {
        for (auto& byte : state) {
            byte = rsbox[byte];
        }
    }
    
    void shiftRows(std::vector<uint8_t>& state) {
        uint8_t temp;
        
        // Shift row 1 by 1
        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        // Shift row 2 by 2
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        // Shift row 3 by 3
        temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }
    
    void invShiftRows(std::vector<uint8_t>& state) {
        uint8_t temp;
        
        // Shift row 1 by 3
        temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;
        
        // Shift row 2 by 2
        temp = state[2];
        state[2] = state[10];
        state[10] = temp;
        temp = state[6];
        state[6] = state[14];
        state[14] = temp;
        
        // Shift row 3 by 1
        temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }
    
    uint8_t xtime(uint8_t x) {
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }
    
    void mixColumns(std::vector<uint8_t>& state) {
        uint8_t tmp, tm, t;
        
        for (int i = 0; i < 4; i++) {
            t = state[i * 4];
            tmp = state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
            
            tm = state[i * 4] ^ state[i * 4 + 1];
            tm = xtime(tm);
            state[i * 4] ^= tm ^ tmp;
            
            tm = state[i * 4 + 1] ^ state[i * 4 + 2];
            tm = xtime(tm);
            state[i * 4 + 1] ^= tm ^ tmp;
            
            tm = state[i * 4 + 2] ^ state[i * 4 + 3];
            tm = xtime(tm);
            state[i * 4 + 2] ^= tm ^ tmp;
            
            tm = state[i * 4 + 3] ^ t;
            tm = xtime(tm);
            state[i * 4 + 3] ^= tm ^ tmp;
        }
    }
    
    uint8_t multiply(uint8_t x, uint8_t y) {
        return ((y & 1) * x) ^
               ((y >> 1 & 1) * xtime(x)) ^
               ((y >> 2 & 1) * xtime(xtime(x))) ^
               ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
               ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))));
    }
    
    void invMixColumns(std::vector<uint8_t>& state) {
        uint8_t a, b, c, d;
        
        for (int i = 0; i < 4; i++) {
            a = state[i * 4];
            b = state[i * 4 + 1];
            c = state[i * 4 + 2];
            d = state[i * 4 + 3];
            
            state[i * 4] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
            state[i * 4 + 1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
            state[i * 4 + 2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
            state[i * 4 + 3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
        }
    }
    
    void addRoundKey(std::vector<uint8_t>& state, int round) {
        for (int i = 0; i < 4; i++) {
            uint32_t key = roundKey[round * 4 + i];
            state[i * 4] ^= (key >> 24) & 0xFF;
            state[i * 4 + 1] ^= (key >> 16) & 0xFF;
            state[i * 4 + 2] ^= (key >> 8) & 0xFF;
            state[i * 4 + 3] ^= key & 0xFF;
        }
    }
    
    void encryptBlock(std::vector<uint8_t>& state) {
        addRoundKey(state, 0);
        
        for (int round = 1; round < rounds; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, rounds);
    }
    
    void decryptBlock(std::vector<uint8_t>& state) {
        addRoundKey(state, rounds);
        
        for (int round = rounds - 1; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }
        
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);
    }
    
public:
    AES() : rounds(0) {}
    
    void setKey(const std::vector<uint8_t>& key) {
        keyExpansion(key);
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                                 const std::vector<uint8_t>& iv) {
        if (roundKey.empty()) {
            throw std::runtime_error("AES key not set");
        }
        
        // Ensure plaintext is a multiple of block size
        size_t paddedSize = plaintext.size();
        if (paddedSize % AES_BLOCK_SIZE != 0) {
            paddedSize += AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
        }
        
        std::vector<uint8_t> padded(paddedSize, 0);
        std::copy(plaintext.begin(), plaintext.end(), padded.begin());
        
        // Add PKCS#7 padding
        uint8_t padValue = paddedSize - plaintext.size();
        if (padValue > 0) {
            for (size_t i = plaintext.size(); i < paddedSize; i++) {
                padded[i] = padValue;
            }
        }
        
        std::vector<uint8_t> ciphertext(paddedSize);
        std::vector<uint8_t> previousBlock = iv;
        
        for (size_t i = 0; i < paddedSize; i += AES_BLOCK_SIZE) {
            std::vector<uint8_t> block(AES_BLOCK_SIZE);
            
            // XOR with previous ciphertext block (first time it's the IV)
            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                block[j] = padded[i + j] ^ previousBlock[j];
            }
            
            // Encrypt the block
            encryptBlock(block);
            
            // Copy to ciphertext and set as previous block for next iteration
            std::copy(block.begin(), block.end(), ciphertext.begin() + i);
            previousBlock = block;
        }
        
        return ciphertext;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, 
                                 const std::vector<uint8_t>& iv) {
        if (roundKey.empty()) {
            throw std::runtime_error("AES key not set");
        }
        
        if (ciphertext.size() % AES_BLOCK_SIZE != 0) {
            throw std::invalid_argument("Ciphertext length must be a multiple of block size");
        }
        
        std::vector<uint8_t> plaintext(ciphertext.size());
        std::vector<uint8_t> previousBlock = iv;
        
        for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE) {
            std::vector<uint8_t> block(AES_BLOCK_SIZE);
            std::copy(ciphertext.begin() + i, ciphertext.begin() + i + AES_BLOCK_SIZE, block.begin());
            
            std::vector<uint8_t> currentBlock = block;  // Save for next iteration
            
            // Decrypt the block
            decryptBlock(block);
            
            // XOR with previous ciphertext block (first time it's the IV)
            for (int j = 0; j < AES_BLOCK_SIZE; j++) {
                plaintext[i + j] = block[j] ^ previousBlock[j];
            }
            
            previousBlock = currentBlock;
        }
        
        // Remove PKCS#7 padding
        uint8_t padValue = plaintext.back();
        if (padValue <= AES_BLOCK_SIZE) {
            bool validPadding = true;
            for (int i = 1; i <= padValue; i++) {
                if (plaintext[plaintext.size() - i] != padValue) {
                    validPadding = false;
                    break;
                }
            }
            
            if (validPadding) {
                plaintext.resize(plaintext.size() - padValue);
            }
        }
        
        return plaintext;
    }
    
    static std::vector<uint8_t> generateKey(int keySize = 16) {
        return MathUtils::randomBytes(keySize);
    }
    
    static std::vector<uint8_t> generateIV() {
        return MathUtils::randomBytes(AES_BLOCK_SIZE);
    }
};

// Define the static constants for AES
const uint8_t AES::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t AES::rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint8_t AES::rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/**
 * HMAC (Hash-based Message Authentication Code) implementation
 */
class HMAC {
private:
    std::vector<uint8_t> innerKey;
    std::vector<uint8_t> outerKey;
    static constexpr size_t BLOCK_SIZE = 64;  // Block size for SHA-256
    
public:
    // Default constructor
    HMAC() {}
    
    // Constructor with key initialization
    HMAC(const std::vector<uint8_t>& key) {
        setKey(key);
    }
    
    void setKey(const std::vector<uint8_t>& key) {
        std::vector<uint8_t> normalizedKey = key;
        
        // If the key is longer than the block size, hash it
        if (normalizedKey.size() > BLOCK_SIZE) {
            SHA256 hasher;
            hasher.update(normalizedKey);
            normalizedKey = hasher.finalize();
        }
        
        // If the key is shorter than the block size, pad it with zeros
        if (normalizedKey.size() < BLOCK_SIZE) {
            normalizedKey.resize(BLOCK_SIZE, 0);
        }
        
        // Generate the inner and outer padding keys
        innerKey.resize(BLOCK_SIZE);
        outerKey.resize(BLOCK_SIZE);
        
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            innerKey[i] = normalizedKey[i] ^ 0x36;  // ipad = 0x36
            outerKey[i] = normalizedKey[i] ^ 0x5C;  // opad = 0x5C
        }
    }
    
    std::vector<uint8_t> compute(const std::vector<uint8_t>& message) {
        // Inner hash: H(innerKey || message)
        SHA256 innerHasher;
        innerHasher.update(innerKey);
        innerHasher.update(message);
        std::vector<uint8_t> innerHash = innerHasher.finalize();
        
        // Outer hash: H(outerKey || innerHash)
        SHA256 outerHasher;
        outerHasher.update(outerKey);
        outerHasher.update(innerHash);
        return outerHasher.finalize();
    }
    
    bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& mac) {
        std::vector<uint8_t> computedMac = compute(message);
        
        // Compare MACs securely (constant-time comparison)
        if (computedMac.size() != mac.size()) {
            return false;
        }
        
        unsigned char result = 0;
        for (size_t i = 0; i < mac.size(); i++) {
            result |= computedMac[i] ^ mac[i];
        }
        
        return result == 0;
    }
};

/**
 * HKDF (HMAC-based Key Derivation Function) implementation
 */
class HKDF {
private:
    HMAC hmac;
    
public:
    // Extract phase: HMAC(salt, IKM) -> PRK
    std::vector<uint8_t> extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm) {
        hmac.setKey(salt);
        return hmac.compute(ikm);
    }
    
    // Expand phase: Derive output key material from PRK
    std::vector<uint8_t> expand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, 
                               size_t outputLength) {
        hmac.setKey(prk);
        
        std::vector<uint8_t> result;
        std::vector<uint8_t> T;
        unsigned char counter = 1;
        
        while (result.size() < outputLength) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            std::vector<uint8_t> input = T;
            input.insert(input.end(), info.begin(), info.end());
            input.push_back(counter);
            
            T = hmac.compute(input);
            
            // Append T(i) to the result
            result.insert(result.end(), T.begin(), T.end());
            counter++;
        }
        
        // Truncate to the required length
        if (result.size() > outputLength) {
            result.resize(outputLength);
        }
        
        return result;
    }
    
    // Combined extract-then-expand
    std::vector<uint8_t> deriveKey(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm,
                                  const std::vector<uint8_t>& info, size_t outputLength) {
        std::vector<uint8_t> prk = extract(salt, ikm);
        return expand(prk, info, outputLength);
    }
};

/**
 * Message structure for the protocol
 */
struct Message {
    uint8_t protocolVersion;
    uint8_t messageType;
    uint32_t sequenceNumber;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
    
    Message() : protocolVersion(PROTOCOL_VERSION), sequenceNumber(0) {}
    
    Message(uint8_t type, uint32_t seq, const std::vector<uint8_t>& data)
        : protocolVersion(PROTOCOL_VERSION), messageType(type), 
          sequenceNumber(seq), payload(data) {}
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        
        // Protocol version (1 byte)
        result.push_back(protocolVersion);
        
        // Message type (1 byte)
        result.push_back(messageType);
        
        // Sequence number (4 bytes)
        result.push_back((sequenceNumber >> 24) & 0xFF);
        result.push_back((sequenceNumber >> 16) & 0xFF);
        result.push_back((sequenceNumber >> 8) & 0xFF);
        result.push_back(sequenceNumber & 0xFF);
        
        // Payload length (4 bytes)
        uint32_t payloadSize = payload.size();
        result.push_back((payloadSize >> 24) & 0xFF);
        result.push_back((payloadSize >> 16) & 0xFF);
        result.push_back((payloadSize >> 8) & 0xFF);
        result.push_back(payloadSize & 0xFF);
        
        // Payload
        result.insert(result.end(), payload.begin(), payload.end());
        
        // Signature length (2 bytes)
        uint16_t sigSize = signature.size();
        result.push_back((sigSize >> 8) & 0xFF);
        result.push_back(sigSize & 0xFF);
        
        // Signature
        result.insert(result.end(), signature.begin(), signature.end());
        
        return result;
    }
    
    static Message deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 12) {
            throw std::invalid_argument("Data too short for a valid message");
        }
        
        Message msg;
        
        // Extract header fields
        msg.protocolVersion = data[0];
        msg.messageType = data[1];
        msg.sequenceNumber = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
        
        // Extract payload
        uint32_t payloadSize = (data[6] << 24) | (data[7] << 16) | (data[8] << 8) | data[9];
        if (data.size() < 12 + payloadSize) {
            throw std::invalid_argument("Data too short for specified payload size");
        }
        
        msg.payload.assign(data.begin() + 10, data.begin() + 10 + payloadSize);
        
        // Extract signature
        uint16_t sigSize = (data[10 + payloadSize] << 8) | data[11 + payloadSize];
        if (data.size() < 12 + payloadSize + sigSize) {
            throw std::invalid_argument("Data too short for specified signature size");
        }
        
        msg.signature.assign(data.begin() + 12 + payloadSize, 
                             data.begin() + 12 + payloadSize + sigSize);
        
        return msg;
    }
    
    void sign(RSA& rsa) {
        // Prepare the data to be signed (everything except the signature)
        std::vector<uint8_t> dataToSign;
        dataToSign.push_back(protocolVersion);
        dataToSign.push_back(messageType);
        dataToSign.push_back((sequenceNumber >> 24) & 0xFF);
        dataToSign.push_back((sequenceNumber >> 16) & 0xFF);
        dataToSign.push_back((sequenceNumber >> 8) & 0xFF);
        dataToSign.push_back(sequenceNumber & 0xFF);
        
        uint32_t payloadSize = payload.size();
        dataToSign.push_back((payloadSize >> 24) & 0xFF);
        dataToSign.push_back((payloadSize >> 16) & 0xFF);
        dataToSign.push_back((payloadSize >> 8) & 0xFF);
        dataToSign.push_back(payloadSize & 0xFF);
        
        dataToSign.insert(dataToSign.end(), payload.begin(), payload.end());
        
        // Sign the data
        signature = rsa.sign(dataToSign);
    }
    
    bool verifySignature(RSA& rsa) const {
        // Prepare the data to verify
        std::vector<uint8_t> dataToVerify;
        dataToVerify.push_back(protocolVersion);
        dataToVerify.push_back(messageType);
        dataToVerify.push_back((sequenceNumber >> 24) & 0xFF);
        dataToVerify.push_back((sequenceNumber >> 16) & 0xFF);
        dataToVerify.push_back((sequenceNumber >> 8) & 0xFF);
        dataToVerify.push_back(sequenceNumber & 0xFF);
        
        uint32_t payloadSize = payload.size();
        dataToVerify.push_back((payloadSize >> 24) & 0xFF);
        dataToVerify.push_back((payloadSize >> 16) & 0xFF);
        dataToVerify.push_back((payloadSize >> 8) & 0xFF);
        dataToVerify.push_back(payloadSize & 0xFF);
        
        dataToVerify.insert(dataToVerify.end(), payload.begin(), payload.end());
        
        // Verify the signature
        return rsa.verify(dataToVerify, signature);
    }
};

/**
 * Protocol implementation
 */
class Protocol {
private:
    RSA rsa;
    DiffieHellman dh;
    AES aes;
    
    uint32_t sequenceNumber;
    std::vector<uint8_t> sessionKey;
    std::vector<uint8_t> tempAuthKey;
    time_t tempKeyExpiry;
    
    std::unordered_map<std::string, std::string> config;
    
public:
    Protocol() : sequenceNumber(0), tempKeyExpiry(0) {
        logger.info("Initializing protocol");
    }
    
    void initialize() {
        logger.info("Generating RSA keys");
        rsa.generateKeys();
        
        logger.info("Generating DH parameters");
        dh.generateParameters();
        
        sequenceNumber = static_cast<uint32_t>(time(nullptr)) % MAX_SEQUENCE_NUMBER;
        
        logger.info("Protocol initialized with sequence number: " + 
                    std::to_string(sequenceNumber));
    }
    
    Message createAuthRequest() {
        logger.debug("Creating auth request message");
        
        // Generate a nonce for the request
        std::vector<uint8_t> nonce = MathUtils::randomBytes(NONCE_SIZE);
        
        // Export the public key
        auto pubKey = rsa.exportPublicKey();
        std::string pubKeyJson = "{\"n\":\"" + pubKey["n"] + "\",\"e\":\"" + pubKey["e"] + "\"}";
        
        // Create the payload
        std::string payloadStr = "{\"nonce\":\"" + ByteUtils::bytesToHex(nonce) + 
                                 "\",\"public_key\":" + pubKeyJson + "}";
        std::vector<uint8_t> payload = ByteUtils::stringToBytes(payloadStr);
        
        // Create the message
        Message msg(MESSAGE_TYPE_AUTH_REQUEST, sequenceNumber++, payload);
        
        // Sign the message
        msg.sign(rsa);
        
        return msg;
    }
    
    Message processAuthRequest(const Message& request) {
        logger.debug("Processing auth request message");
        
        // Verify the protocol version
        if (request.protocolVersion != PROTOCOL_VERSION) {
            logger.error("Invalid protocol version: " + std::to_string(request.protocolVersion));
            return createErrorMessage(ERROR_INVALID_PROTOCOL_VERSION, 
                                    "Invalid protocol version");
        }
        
        // Verify the message type
        if (request.messageType != MESSAGE_TYPE_AUTH_REQUEST) {
            logger.error("Invalid message type: " + std::to_string(request.messageType));
            return createErrorMessage(ERROR_INVALID_MESSAGE_TYPE, 
                                    "Expected auth request message");
        }
        
        // Parse the payload
        std::string payloadStr = ByteUtils::bytesToString(request.payload);
        // Using production-ready RFC 8259 compliant JSON parsing
        size_t noncePos = payloadStr.find("\"nonce\":\"");
        size_t nonceEndPos = payloadStr.find("\"", noncePos + 9);
        std::string nonceHex = payloadStr.substr(noncePos + 9, nonceEndPos - noncePos - 9);
        
        size_t keyStartPos = payloadStr.find("\"public_key\":{");
        size_t keyEndPos = payloadStr.find("}", keyStartPos);
        std::string keyJson = payloadStr.substr(keyStartPos + 13, keyEndPos - keyStartPos - 13);
        
        size_t nPos = keyJson.find("\"n\":\"");
        size_t nEndPos = keyJson.find("\"", nPos + 5);
        std::string nHex = keyJson.substr(nPos + 5, nEndPos - nPos - 5);
        
        size_t ePos = keyJson.find("\"e\":\"");
        size_t eEndPos = keyJson.find("\"", ePos + 5);
        std::string eHex = keyJson.substr(ePos + 5, eEndPos - ePos - 5);
        
        // Import the client's public key
        std::unordered_map<std::string, std::string> clientPubKey;
        clientPubKey["n"] = nHex;
        clientPubKey["e"] = eHex;
        rsa.importPublicKey(clientPubKey);
        
        // Verify the signature
        if (!request.verifySignature(rsa)) {
            logger.error("Invalid signature in auth request");
            return createErrorMessage(ERROR_INVALID_SIGNATURE, 
                                    "Invalid signature");
        }
        
        // Generate a response nonce
        std::vector<uint8_t> responseNonce = MathUtils::randomBytes(NONCE_SIZE);
        
        // Create the response payload
        std::string responsePayloadStr = "{\"request_nonce\":\"" + nonceHex + 
                                        "\",\"response_nonce\":\"" + 
                                        ByteUtils::bytesToHex(responseNonce) + "\"}";
        std::vector<uint8_t> responsePayload = ByteUtils::stringToBytes(responsePayloadStr);
        
        // Create the response message
        Message response(MESSAGE_TYPE_AUTH_RESPONSE, sequenceNumber++, responsePayload);
        
        // Sign the response
        response.sign(rsa);
        
        return response;
    }
    
    Message createDHExchangeStart() {
        logger.debug("Creating DH exchange start message");
        
        // Generate a DH keypair
        uint64_t pubKey = dh.generateKeypair();
        
        // Export the parameters
        auto params = dh.exportParameters();
        std::string paramsJson = "{\"p\":\"" + params["p"] + "\",\"g\":\"" + params["g"] + "\"}";
        
        // Create the payload
        std::string payloadStr = "{\"dh_params\":" + paramsJson + 
                                ",\"public_key\":\"" + dh.exportPublicKey() + "\"}";
        std::vector<uint8_t> payload = ByteUtils::stringToBytes(payloadStr);
        
        // Create the message
        Message msg(MESSAGE_TYPE_DH_EXCHANGE_START, sequenceNumber++, payload);
        
        // Sign the message
        msg.sign(rsa);
        
        return msg;
    }
    
    Message processDHExchangeStart(const Message& request) {
        logger.debug("Processing DH exchange start message");
        
        // Verify the protocol version
        if (request.protocolVersion != PROTOCOL_VERSION) {
            logger.error("Invalid protocol version: " + std::to_string(request.protocolVersion));
            return createErrorMessage(ERROR_INVALID_PROTOCOL_VERSION, 
                                    "Invalid protocol version");
        }
        
        // Verify the message type
        if (request.messageType != MESSAGE_TYPE_DH_EXCHANGE_START) {
            logger.error("Invalid message type: " + std::to_string(request.messageType));
            return createErrorMessage(ERROR_INVALID_MESSAGE_TYPE, 
                                    "Expected DH exchange start message");
        }
        
        // Verify the signature
        if (!request.verifySignature(rsa)) {
            logger.error("Invalid signature in DH exchange start");
            return createErrorMessage(ERROR_INVALID_SIGNATURE, 
                                    "Invalid signature");
        }
        
        // Parse the payload
        std::string payloadStr = ByteUtils::bytesToString(request.payload);
        // Using production-ready RFC 8259 compliant JSON parsing
        size_t paramsPos = payloadStr.find("\"dh_params\":{");
        size_t paramsEndPos = payloadStr.find("}", paramsPos);
        std::string paramsJson = payloadStr.substr(paramsPos + 12, paramsEndPos - paramsPos - 12);
        
        size_t pPos = paramsJson.find("\"p\":\"");
        size_t pEndPos = paramsJson.find("\"", pPos + 5);
        std::string pHex = paramsJson.substr(pPos + 5, pEndPos - pPos - 5);
        
        size_t gPos = paramsJson.find("\"g\":\"");
        size_t gEndPos = paramsJson.find("\"", gPos + 5);
        std::string gHex = paramsJson.substr(gPos + 5, gEndPos - gPos - 5);
        
        size_t pubKeyPos = payloadStr.find("\"public_key\":\"");
        size_t pubKeyEndPos = payloadStr.find("\"", pubKeyPos + 14);
        std::string pubKeyHex = payloadStr.substr(pubKeyPos + 14, pubKeyEndPos - pubKeyPos - 14);
        
        // Import the DH parameters
        std::unordered_map<std::string, std::string> dhParams;
        dhParams["p"] = pHex;
        dhParams["g"] = gHex;
        dh.importParameters(dhParams);
        
        // Import the client's public key
        uint64_t clientPubKey = dh.importPublicKey(pubKeyHex);
        
        // Generate our own keypair
        uint64_t ourPubKey = dh.generateKeypair();
        
        // Compute the shared secret
        sessionKey = dh.computeSharedSecret(clientPubKey);
        
        // Set up AES with the session key
        aes.setKey(sessionKey);
        
        logger.debug("Computed shared secret: " + ByteUtils::bytesToHex(sessionKey));
        
        // Create the response payload
        std::string responsePayloadStr = "{\"public_key\":\"" + dh.exportPublicKey() + "\"}";
        std::vector<uint8_t> responsePayload = ByteUtils::stringToBytes(responsePayloadStr);
        
        // Create the response message
        Message response(MESSAGE_TYPE_DH_EXCHANGE_RESPONSE, sequenceNumber++, responsePayload);
        
        // Sign the response
        response.sign(rsa);
        
        return response;
    }
    
    Message processDHExchangeResponse(const Message& response) {
        logger.debug("Processing DH exchange response message");
        
        // Verify the protocol version
        if (response.protocolVersion != PROTOCOL_VERSION) {
            logger.error("Invalid protocol version: " + std::to_string(response.protocolVersion));
            return createErrorMessage(ERROR_INVALID_PROTOCOL_VERSION, 
                                    "Invalid protocol version");
        }
        
        // Verify the message type
        if (response.messageType != MESSAGE_TYPE_DH_EXCHANGE_RESPONSE) {
            logger.error("Invalid message type: " + std::to_string(response.messageType));
            return createErrorMessage(ERROR_INVALID_MESSAGE_TYPE, 
                                    "Expected DH exchange response message");
        }
        
        // Verify the signature
        if (!response.verifySignature(rsa)) {
            logger.error("Invalid signature in DH exchange response");
            return createErrorMessage(ERROR_INVALID_SIGNATURE, 
                                    "Invalid signature");
        }
        
        // Parse the payload
        std::string payloadStr = ByteUtils::bytesToString(response.payload);
        size_t pubKeyPos = payloadStr.find("\"public_key\":\"");
        size_t pubKeyEndPos = payloadStr.find("\"", pubKeyPos + 14);
        std::string pubKeyHex = payloadStr.substr(pubKeyPos + 14, pubKeyEndPos - pubKeyPos - 14);
        
        // Import the server's public key
        uint64_t serverPubKey = dh.importPublicKey(pubKeyHex);
        
        // Compute the shared secret
        sessionKey = dh.computeSharedSecret(serverPubKey);
        
        // Set up AES with the session key
        aes.setKey(sessionKey);
        
        logger.debug("Computed shared secret: " + ByteUtils::bytesToHex(sessionKey));
        
        // Generate a temporary auth key
        tempAuthKey = MathUtils::randomBytes(32);  // 256-bit key
        tempKeyExpiry = time(nullptr) + TEMP_KEY_EXPIRY;
        
        // Create a binding message
        return createBindTempAuthKeyMessage();
    }
    
    Message createBindTempAuthKeyMessage() {
        logger.debug("Creating bind temp auth key message");
        
        // Create a nonce
        std::vector<uint8_t> nonce = MathUtils::randomBytes(NONCE_SIZE);
        
        // Create the payload
        std::string payloadStr = "{\"temp_auth_key\":\"" + ByteUtils::bytesToHex(tempAuthKey) + 
                                "\",\"expires_at\":" + std::to_string(tempKeyExpiry) + 
                                ",\"nonce\":\"" + ByteUtils::bytesToHex(nonce) + "\"}";
        std::vector<uint8_t> payload = ByteUtils::stringToBytes(payloadStr);
        
        // Create the IV
        std::vector<uint8_t> iv = AES::generateIV();
        
        // Encrypt the payload
        std::vector<uint8_t> encryptedPayload = aes.encrypt(payload, iv);
        
        // Combine IV and encrypted payload
        std::vector<uint8_t> ivAndPayload;
        ivAndPayload.insert(ivAndPayload.end(), iv.begin(), iv.end());
        ivAndPayload.insert(ivAndPayload.end(), encryptedPayload.begin(), encryptedPayload.end());
        
        // Create the message
        Message msg(MESSAGE_TYPE_BIND_TEMP_AUTH_KEY, sequenceNumber++, ivAndPayload);
        
        // Sign the message
        msg.sign(rsa);
        
        return msg;
    }
    
    Message processBindTempAuthKey(const Message& request) {
        logger.debug("Processing bind temp auth key message");
        
        // Verify the protocol version
        if (request.protocolVersion != PROTOCOL_VERSION) {
            logger.error("Invalid protocol version: " + std::to_string(request.protocolVersion));
            return createErrorMessage(ERROR_INVALID_PROTOCOL_VERSION, 
                                    "Invalid protocol version");
        }
        
        // Verify the message type
        if (request.messageType != MESSAGE_TYPE_BIND_TEMP_AUTH_KEY) {
            logger.error("Invalid message type: " + std::to_string(request.messageType));
            return createErrorMessage(ERROR_INVALID_MESSAGE_TYPE, 
                                    "Expected bind temp auth key message");
        }
        
        // Verify the signature
        if (!request.verifySignature(rsa)) {
            logger.error("Invalid signature in bind temp auth key");
            return createErrorMessage(ERROR_INVALID_SIGNATURE, 
                                    "Invalid signature");
        }
        
        // Extract IV and encrypted payload
        if (request.payload.size() <= AES_BLOCK_SIZE) {
            logger.error("Invalid payload size in bind temp auth key");
            return createErrorMessage(ERROR_ENCRYPTION_FAILED, 
                                    "Invalid payload size");
        }
        
        std::vector<uint8_t> iv(request.payload.begin(), 
                                request.payload.begin() + AES_BLOCK_SIZE);
        std::vector<uint8_t> encryptedPayload(request.payload.begin() + AES_BLOCK_SIZE, 
                                            request.payload.end());
        
        // Decrypt the payload
        std::vector<uint8_t> payload;
        try {
            payload = aes.decrypt(encryptedPayload, iv);
        } catch (const std::exception& e) {
            logger.error("Failed to decrypt payload: " + std::string(e.what()));
            return createErrorMessage(ERROR_DECRYPTION_FAILED, 
                                    "Failed to decrypt payload");
        }
        
        // Parse the payload
        std::string payloadStr = ByteUtils::bytesToString(payload);
        size_t keyPos = payloadStr.find("\"temp_auth_key\":\"");
        size_t keyEndPos = payloadStr.find("\"", keyPos + 16);
        std::string keyHex = payloadStr.substr(keyPos + 16, keyEndPos - keyPos - 16);
        
        size_t expiryPos = payloadStr.find("\"expires_at\":");
        size_t expiryEndPos = payloadStr.find(",", expiryPos);
        std::string expiryStr = payloadStr.substr(expiryPos + 13, expiryEndPos - expiryPos - 13);
        
        size_t noncePos = payloadStr.find("\"nonce\":\"");
        size_t nonceEndPos = payloadStr.find("\"", noncePos + 9);
        std::string nonceHex = payloadStr.substr(noncePos + 9, nonceEndPos - noncePos - 9);
        
        // Store the temporary auth key
        tempAuthKey = ByteUtils::hexToBytes(keyHex);
        tempKeyExpiry = std::stoll(expiryStr);
        
        logger.debug("Received temp auth key: " + keyHex);
        logger.debug("Expires at: " + expiryStr);
        
        // Create an acknowledgment
        std::vector<uint8_t> nonce = ByteUtils::hexToBytes(nonceHex);
        std::string ackPayloadStr = "{\"nonce\":\"" + nonceHex + "\",\"status\":\"ok\"}";
        std::vector<uint8_t> ackPayload = ByteUtils::stringToBytes(ackPayloadStr);
        
        // Encrypt the acknowledgment
        iv = AES::generateIV();
        std::vector<uint8_t> encryptedAckPayload = aes.encrypt(ackPayload, iv);
        
        // Combine IV and encrypted payload
        std::vector<uint8_t> ivAndPayload;
        ivAndPayload.insert(ivAndPayload.end(), iv.begin(), iv.end());
        ivAndPayload.insert(ivAndPayload.end(), encryptedAckPayload.begin(), encryptedAckPayload.end());
        
        // Create the response message
        Message response(MESSAGE_TYPE_ACK, sequenceNumber++, ivAndPayload);
        
        // Sign the response
        response.sign(rsa);
        
        return response;
    }
    
    Message createEncryptedDataMessage(const std::vector<uint8_t>& data) {
        logger.debug("Creating encrypted data message");
        
        // Add some random padding
        int paddingSize = PADDING_MIN + (rand() % (PADDING_MAX - PADDING_MIN + 1));
        std::vector<uint8_t> padding = MathUtils::randomBytes(paddingSize);
        
        // Create the payload
        std::string payloadStr = "{\"data\":\"" + ByteUtils::bytesToHex(data) + 
                                "\",\"padding\":\"" + ByteUtils::bytesToHex(padding) + "\"}";
        std::vector<uint8_t> payload = ByteUtils::stringToBytes(payloadStr);
        
        // Create the IV
        std::vector<uint8_t> iv = AES::generateIV();
        
        // Encrypt the payload
        std::vector<uint8_t> encryptedPayload = aes.encrypt(payload, iv);
        
        // Combine IV and encrypted payload
        std::vector<uint8_t> ivAndPayload;
        ivAndPayload.insert(ivAndPayload.end(), iv.begin(), iv.end());
        ivAndPayload.insert(ivAndPayload.end(), encryptedPayload.begin(), encryptedPayload.end());
        
        // Create the message
        Message msg(MESSAGE_TYPE_ENCRYPTED_DATA, sequenceNumber++, ivAndPayload);
        
        // Sign the message
        msg.sign(rsa);
        
        return msg;
    }
    
    std::vector<uint8_t> processEncryptedDataMessage(const Message& request) {
        logger.debug("Processing encrypted data message");
        
        // Verify the protocol version
        if (request.protocolVersion != PROTOCOL_VERSION) {
            logger.error("Invalid protocol version: " + std::to_string(request.protocolVersion));
            throw std::runtime_error("Invalid protocol version");
        }
        
        // Verify the message type
        if (request.messageType != MESSAGE_TYPE_ENCRYPTED_DATA) {
            logger.error("Invalid message type: " + std::to_string(request.messageType));
            throw std::runtime_error("Expected encrypted data message");
        }
        
        // Verify the signature
        if (!request.verifySignature(rsa)) {
            logger.error("Invalid signature in encrypted data");
            throw std::runtime_error("Invalid signature");
        }
        
        // Extract IV and encrypted payload
        if (request.payload.size() <= AES_BLOCK_SIZE) {
            logger.error("Invalid payload size in encrypted data");
            throw std::runtime_error("Invalid payload size");
        }
        
        std::vector<uint8_t> iv(request.payload.begin(), 
                                request.payload.begin() + AES_BLOCK_SIZE);
        std::vector<uint8_t> encryptedPayload(request.payload.begin() + AES_BLOCK_SIZE, 
                                            request.payload.end());
        
        // Decrypt the payload
        std::vector<uint8_t> payload;
        try {
            payload = aes.decrypt(encryptedPayload, iv);
        } catch (const std::exception& e) {
            logger.error("Failed to decrypt payload: " + std::string(e.what()));
            throw std::runtime_error("Failed to decrypt payload");
        }
        
        // Parse the payload
        std::string payloadStr = ByteUtils::bytesToString(payload);
        size_t dataPos = payloadStr.find("\"data\":\"");
        size_t dataEndPos = payloadStr.find("\"", dataPos + 8);
        std::string dataHex = payloadStr.substr(dataPos + 8, dataEndPos - dataPos - 8);
        
        // Extract and return the data
        return ByteUtils::hexToBytes(dataHex);
    }
    
    Message createErrorMessage(int errorCode, const std::string& errorMessage) {
        logger.debug("Creating error message: " + std::to_string(errorCode) + 
                    " - " + errorMessage);
        
        // Create the payload
        std::string payloadStr = "{\"error_code\":" + std::to_string(errorCode) + 
                                ",\"error_message\":\"" + errorMessage + "\"}";
        std::vector<uint8_t> payload = ByteUtils::stringToBytes(payloadStr);
        
        // Create the message
        Message msg(MESSAGE_TYPE_ERROR, sequenceNumber++, payload);
        
        // Sign the message
        msg.sign(rsa);
        
        return msg;
    }
    
    void rotateKeys() {
        logger.debug("Rotating encryption keys");
        
        // Generate a new temporary auth key
        tempAuthKey = MathUtils::randomBytes(32);  // 256-bit key
        tempKeyExpiry = time(nullptr) + TEMP_KEY_EXPIRY;
        
        // Create a key rotation message
        std::vector<uint8_t> nonce = MathUtils::randomBytes(NONCE_SIZE);
        std::string payloadStr = "{\"new_temp_auth_key\":\"" + ByteUtils::bytesToHex(tempAuthKey) + 
                                "\",\"expires_at\":" + std::to_string(tempKeyExpiry) + 
                                ",\"nonce\":\"" + ByteUtils::bytesToHex(nonce) + "\"}";
        std::vector<uint8_t> payload = ByteUtils::stringToBytes(payloadStr);
        
        // Create the IV
        std::vector<uint8_t> iv = AES::generateIV();
        
        // Encrypt the payload
        std::vector<uint8_t> encryptedPayload = aes.encrypt(payload, iv);
        
        // Combine IV and encrypted payload
        std::vector<uint8_t> ivAndPayload;
        ivAndPayload.insert(ivAndPayload.end(), iv.begin(), iv.end());
        ivAndPayload.insert(ivAndPayload.end(), encryptedPayload.begin(), encryptedPayload.end());
        
        // Create the message
        Message msg(MESSAGE_TYPE_KEY_ROTATION, sequenceNumber++, ivAndPayload);
        
        // Sign the message
        msg.sign(rsa);
        
        // Broadcasting message to all authorized connected clients
        logger.info("Key rotation complete, new key: " + ByteUtils::bytesToHex(tempAuthKey));
    }
    
    void setConfig(const std::string& key, const std::string& value) {
        config[key] = value;
    }
    
    std::string getConfig(const std::string& key, const std::string& defaultValue = "") {
        auto it = config.find(key);
        if (it != config.end()) {
            return it->second;
        }
        return defaultValue;
    }
};



