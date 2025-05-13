#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QListWidget>
#include <QSplitter>
#include <QMessageBox>
#include <QDialog>
#include <QInputDialog>
#include <QDateTime>
#include <QTimer>
#include <QScrollArea>
#include <QScrollBar>
#include <QToolBar>
#include <QAction>
#include <QIcon>
#include <QMenu>
#include <QMenuBar>
#include <QStatusBar>
#include <QFrame>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QHeaderView>
#include <QTableView>
#include <QStandardItemModel>
#include <QSvgWidget>
#include <QBuffer>
#include <QPainter>
#include <QThread>
#include <QSettings>
#include <QStackedWidget>
#include <QRadioButton>
#include <QtConcurrent>
#include <QFuture>

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <algorithm>
#include <functional>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>

// Diffie-Hellman 2048-bit prime from RFC 3526
const std::string DH_PRIME = 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD96"
    "1C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE5"
    "15D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

// Custom SHA-1 implementation
class SHA1 {
private:
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];

    void transform(const unsigned char block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
        uint32_t w[80];

        for (int i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        for (int i = 16; i < 80; i++) {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
            w[i] = (w[i] << 1) | (w[i] >> 31);
        }

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;

            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

public:
    SHA1() {
        reset();
    }

    void reset() {
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
        count[0] = count[1] = 0;
    }

    void update(const void* data, size_t len) {
        const unsigned char* input = static_cast<const unsigned char*>(data);
        size_t i, index, partLen;

        index = (count[0] >> 3) & 0x3F;
        if ((count[0] += (len << 3)) < (len << 3)) count[1]++;
        count[1] += (len >> 29);

        partLen = 64 - index;
        if (len >= partLen) {
            memcpy(&buffer[index], input, partLen);
            transform(buffer);

            for (i = partLen; i + 63 < len; i += 64) {
                transform(&input[i]);
            }
            index = 0;
        } else {
            i = 0;
        }

        memcpy(&buffer[index], &input[i], len - i);
    }

    void final(unsigned char digest[20]) {
        unsigned char finalcount[8];
        for (unsigned i = 0; i < 8; i++) {
            finalcount[i] = static_cast<unsigned char>((count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
        }

        unsigned char c = 0x80;
        update(&c, 1);

        while ((count[0] & 504) != 448) {
            c = 0;
            update(&c, 1);
        }

        update(finalcount, 8);

        for (unsigned i = 0; i < 20; i++) {
            digest[i] = static_cast<unsigned char>((state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
        }
    }

    static std::string hash(const std::string& input) {
        SHA1 sha1;
        unsigned char digest[20];
        
        sha1.update(input.c_str(), input.size());
        sha1.final(digest);
        
        std::stringstream ss;
        for(int i = 0; i < 20; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        
        return ss.str();
    }
};

// Custom SHA-256 implementation
class SHA256 {
private:
    uint32_t state[8];
    uint32_t count[2];
    unsigned char buffer[64];
    
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    static uint32_t ROTR(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    
    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static uint32_t Sigma0(uint32_t x) {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }
    
    static uint32_t Sigma1(uint32_t x) {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }
    
    static uint32_t sigma0(uint32_t x) {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    }
    
    static uint32_t sigma1(uint32_t x) {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
    }
    
    void transform(const unsigned char block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        uint32_t w[64];
        
        for (int i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        
        for (int i = 16; i < 64; i++) {
            w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
        }
        
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            
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
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        count[0] = count[1] = 0;
    }
    
    void update(const void* data, size_t len) {
        const unsigned char* input = static_cast<const unsigned char*>(data);
        size_t i, index, partLen;
        
        index = (count[0] >> 3) & 0x3F;
        if ((count[0] += (len << 3)) < (len << 3)) count[1]++;
        count[1] += (len >> 29);
        
        partLen = 64 - index;
        if (len >= partLen) {
            memcpy(&buffer[index], input, partLen);
            transform(buffer);
            
            for (i = partLen; i + 63 < len; i += 64) {
                transform(&input[i]);
            }
            index = 0;
        } else {
            i = 0;
        }
        
        memcpy(&buffer[index], &input[i], len - i);
    }
    
    void final(unsigned char digest[32]) {
        unsigned char finalcount[8];
        for (unsigned i = 0; i < 8; i++) {
            finalcount[i] = static_cast<unsigned char>((count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
        }
        
        unsigned char c = 0x80;
        update(&c, 1);
        
        while ((count[0] & 504) != 448) {
            c = 0;
            update(&c, 1);
        }
        
        update(finalcount, 8);
        
        for (unsigned i = 0; i < 32; i++) {
            digest[i] = static_cast<unsigned char>((state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
        }
    }
    
    static std::string hash(const std::string& input) {
        SHA256 sha256;
        unsigned char digest[32];
        
        sha256.update(input.c_str(), input.size());
        sha256.final(digest);
        
        std::stringstream ss;
        for(int i = 0; i < 32; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        
        return ss.str();
    }
};

// BigInteger class for handling large integers required for DHKE
class BigInteger {
private:
    std::vector<uint8_t> data; // big endian representation

    void removeLeadingZeros() {
        while (data.size() > 1 && data.front() == 0) {
            data.erase(data.begin());
        }
    }

public:
    BigInteger() : data(1, 0) {}

    BigInteger(const std::string& hexStr) {
        if (hexStr.empty()) {
            data.push_back(0);
            return;
        }

        for (size_t i = 0; i < hexStr.size(); i += 2) {
            std::string byteStr = hexStr.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            data.push_back(byte);
        }

        removeLeadingZeros();
    }

    BigInteger(uint64_t value) {
        do {
            data.insert(data.begin(), value & 0xFF);
            value >>= 8;
        } while (value);
    }

    static BigInteger fromBinary(const std::vector<uint8_t>& binary) {
        BigInteger result;
        result.data = binary;
        result.removeLeadingZeros();
        return result;
    }

    std::vector<uint8_t> toBinary() const {
        return data;
    }

    std::string toHexString() const {
        std::stringstream ss;
        for (uint8_t byte : data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }
    
    // Generate a random BigInteger of specified bit length
    static BigInteger generateRandom(int bits) {
        if (bits <= 0) {
            throw std::invalid_argument("Bit length must be positive");
        }
        
        // Calculate number of bytes needed
        int bytes = (bits + 7) / 8;
        
        // Initialize random generator
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        // Generate random bytes
        std::vector<uint8_t> randomBytes(bytes);
        for (int i = 0; i < bytes; i++) {
            randomBytes[i] = dis(gen);
        }
        
        // Ensure the highest bit is set to meet the bit length requirement
        int highestBit = bits % 8;
        if (highestBit == 0) {
            // If bits is a multiple of 8, set the highest bit of the most significant byte
            randomBytes[0] |= 0x80;
        } else {
            // Otherwise, set the appropriate bit
            randomBytes[0] |= (1 << (highestBit - 1));
        }
        
        BigInteger result;
        result.data = randomBytes;
        return result;
    }

    BigInteger modPow(const BigInteger& exponent, const BigInteger& modulus) const {
        if (modulus.isZero()) {
            throw std::runtime_error("Modulus cannot be zero");
        }
        
        if (modulus.isOne()) {
            return BigInteger(0);
        }

        BigInteger base = *this % modulus;
        BigInteger result(1);
        BigInteger exp = exponent;

        while (!exp.isZero()) {
            if (exp.isOdd()) {
                result = (result * base) % modulus;
            }
            base = (base * base) % modulus;
            exp = exp >> 1;
        }

        return result;
    }

    bool isZero() const {
        return data.size() == 1 && data[0] == 0;
    }

    bool isOne() const {
        return data.size() == 1 && data[0] == 1;
    }

    bool isOdd() const {
        return (data.back() & 1) == 1;
    }

    BigInteger operator+(const BigInteger& other) const {
        std::vector<uint8_t> result;
        int carry = 0;
        
        const std::vector<uint8_t>& a = data;
        const std::vector<uint8_t>& b = other.data;
        
        size_t maxSize = std::max(a.size(), b.size());
        result.resize(maxSize + 1, 0);
        
        for (ssize_t i = a.size() - 1, j = b.size() - 1, k = result.size() - 1; k >= 0; --i, --j, --k) {
            int sum = carry;
            if (i >= 0) sum += a[i];
            if (j >= 0) sum += b[j];
            
            result[k] = sum & 0xFF;
            carry = sum >> 8;
        }
        
        BigInteger res;
        res.data = result;
        res.removeLeadingZeros();
        return res;
    }

    BigInteger operator-(const BigInteger& other) const {
        if (*this < other) {
            throw std::runtime_error("Negative result not supported");
        }
        
        std::vector<uint8_t> result;
        int borrow = 0;
        
        const std::vector<uint8_t>& a = data;
        const std::vector<uint8_t>& b = other.data;
        
        result.resize(a.size(), 0);
        
        for (ssize_t i = a.size() - 1, j = b.size() - 1, k = result.size() - 1; k >= 0; --i, --j, --k) {
            int diff = a[i] - borrow;
            if (j >= 0) diff -= b[j];
            
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            
            result[k] = diff;
        }
        
        BigInteger res;
        res.data = result;
        res.removeLeadingZeros();
        return res;
    }

    BigInteger operator*(const BigInteger& other) const {
        if (isZero() || other.isZero()) {
            return BigInteger(0);
        }
        
        const std::vector<uint8_t>& a = data;
        const std::vector<uint8_t>& b = other.data;
        
        std::vector<uint8_t> result(a.size() + b.size(), 0);
        
        for (ssize_t i = a.size() - 1; i >= 0; --i) {
            int carry = 0;
            for (ssize_t j = b.size() - 1; j >= 0; --j) {
                int temp = result[i + j + 1] + a[i] * b[j] + carry;
                result[i + j + 1] = temp & 0xFF;
                carry = temp >> 8;
            }
            result[i] += carry;
        }
        
        BigInteger res;
        res.data = result;
        res.removeLeadingZeros();
        return res;
    }

    BigInteger operator/(const BigInteger& other) const {
        if (other.isZero()) {
            throw std::runtime_error("Division by zero");
        }
        
        if (*this < other) {
            return BigInteger(0);
        }
        
        if (*this == other) {
            return BigInteger(1);
        }
        
        BigInteger quotient(0);
        BigInteger remainder = *this;
        
        // Compute the number of bits in the dividend and divisor
        int dividendBits = (data.size() * 8);
        int divisorBits = (other.data.size() * 8);
        
        // Align divisor with dividend
        BigInteger divisor = other << (dividendBits - divisorBits);
        BigInteger bitValue = BigInteger(1) << (dividendBits - divisorBits);
        
        while (remainder >= other) {
            if (remainder >= divisor) {
                remainder = remainder - divisor;
                quotient = quotient + bitValue;
            }
            divisor = divisor >> 1;
            bitValue = bitValue >> 1;
        }
        
        return quotient;
    }

    BigInteger operator%(const BigInteger& other) const {
        if (other.isZero()) {
            throw std::runtime_error("Modulo by zero");
        }
        
        if (*this < other) {
            return *this;
        }
        
        if (*this == other) {
            return BigInteger(0);
        }
        
        BigInteger remainder = *this;
        
        // Compute the number of bits in the dividend and divisor
        int dividendBits = (data.size() * 8);
        int divisorBits = (other.data.size() * 8);
        
        // Align divisor with dividend
        BigInteger divisor = other << (dividendBits - divisorBits);
        
        while (remainder >= other) {
            if (remainder >= divisor) {
                remainder = remainder - divisor;
            }
            divisor = divisor >> 1;
        }
        
        return remainder;
    }

    BigInteger operator<<(int shift) const {
        if (shift <= 0) {
            return *this;
        }
        
        int bytesToAdd = shift / 8;
        int bitsToShift = shift % 8;
        
        std::vector<uint8_t> result;
        result.resize(data.size() + bytesToAdd + (bitsToShift > 0 ? 1 : 0), 0);
        
        // Copy existing data with byte-level shift
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i];
        }
        
        // Perform bit-level shift if needed
        if (bitsToShift > 0) {
            for (int i = result.size() - 1; i > bytesToAdd; --i) {
                result[i] = (result[i - bytesToAdd] << bitsToShift) | 
                           (i > bytesToAdd + 1 ? (result[i - bytesToAdd - 1] >> (8 - bitsToShift)) : 0);
            }
            result[bytesToAdd] = result[0] << bitsToShift;
            
            // Set the newly added bytes to zero
            for (int i = 0; i < bytesToAdd; ++i) {
                result[i] = 0;
            }
        } else {
            // Just shift bytes
            for (int i = result.size() - 1; i >= bytesToAdd; --i) {
                result[i] = result[i - bytesToAdd];
            }
            // Set the newly added bytes to zero
            for (int i = 0; i < bytesToAdd; ++i) {
                result[i] = 0;
            }
        }
        
        BigInteger res;
        res.data = result;
        res.removeLeadingZeros();
        return res;
    }

    BigInteger operator>>(int shift) const {
        if (shift <= 0) {
            return *this;
        }
        
        int bytesToRemove = shift / 8;
        int bitsToShift = shift % 8;
        
        if (bytesToRemove >= static_cast<int>(data.size())) {
            return BigInteger(0);
        }
        
        std::vector<uint8_t> result;
        result.resize(data.size() - bytesToRemove, 0);
        
        // Copy existing data with byte-level shift
        for (size_t i = 0; i < result.size(); ++i) {
            result[i] = data[i + bytesToRemove];
        }
        
        // Perform bit-level shift if needed
        if (bitsToShift > 0) {
            for (size_t i = 0; i < result.size() - 1; ++i) {
                result[i] = (result[i] >> bitsToShift) | 
                           (result[i + 1] << (8 - bitsToShift));
            }
            result[result.size() - 1] = result[result.size() - 1] >> bitsToShift;
        }
        
        BigInteger res;
        res.data = result;
        res.removeLeadingZeros();
        return res;
    }

    bool operator<(const BigInteger& other) const {
        if (data.size() < other.data.size()) {
            return true;
        }
        if (data.size() > other.data.size()) {
            return false;
        }
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (data[i] < other.data[i]) {
                return true;
            }
            if (data[i] > other.data[i]) {
                return false;
            }
        }
        
        return false; // Equal
    }

    bool operator>(const BigInteger& other) const {
        return other < *this;
    }

    bool operator<=(const BigInteger& other) const {
        return !(other < *this);
    }

    bool operator>=(const BigInteger& other) const {
        return !(*this < other);
    }

    bool operator==(const BigInteger& other) const {
        return data == other.data;
    }

    bool operator!=(const BigInteger& other) const {
        return !(*this == other);
    }

    // We'll use the first implementation of generateRandom only
};

// Diffie-Hellman key exchange implementation
class DiffieHellman {
private:
    BigInteger p; // Prime modulus
    BigInteger g; // Generator
    BigInteger private_key; // Private key
    BigInteger public_key; // Public key g^a mod p
    std::chrono::time_point<std::chrono::system_clock> creation_time;
    int message_count;
    static const int MESSAGE_THRESHOLD = 100; // Re-key after 100 messages
    static const int TIME_THRESHOLD_DAYS = 7; // Re-key after 1 week

public:
    DiffieHellman(const std::string& primeHex = DH_PRIME, int generator = 2) {
        // Initialize with the provided prime
        p = BigInteger(primeHex);
        g = BigInteger(generator);
        
        // Generate a random private key
        private_key = BigInteger::generateRandom(256); // 256-bit private key
        
        // Calculate public key g^a mod p
        public_key = g.modPow(private_key, p);
        
        // Initialize counters for Perfect Forward Secrecy
        creation_time = std::chrono::system_clock::now();
        message_count = 0;
    }
    
    // Get the public key
    BigInteger getPublicKey() const {
        return public_key;
    }
    
    // Generate a private key
    BigInteger generatePrivateKey() {
        return BigInteger::generateRandom(256); // 256-bit private key
    }
    
    // Generate a public key from a private key
    BigInteger generatePublicKey(const BigInteger& privateKey) {
        return g.modPow(privateKey, p);
    }
    
    // Compute the shared secret given the other party's public key
    BigInteger computeSharedSecret(const BigInteger& otherPublicKey) const {
        // Check that otherPublicKey is valid (greater than 1 and less than p-1)
        BigInteger one(1);
        BigInteger p_minus_1 = p - one;
        
        if (otherPublicKey <= one || otherPublicKey >= p_minus_1) {
            throw std::runtime_error("Invalid public key value");
        }
        
        // Additional security check: verify public key is in proper range
        // Recommended: check g_a and g_b are between 2^{2048-64} and p - 2^{2048-64}
        BigInteger min_threshold = BigInteger(1) << (2048 - 64);
        BigInteger max_threshold = p - min_threshold;
        
        if (otherPublicKey < min_threshold || otherPublicKey > max_threshold) {
            throw std::runtime_error("Public key outside secure range");
        }
        
        // Shared secret = (otherPublicKey)^private_key mod p
        BigInteger shared_secret = otherPublicKey.modPow(private_key, p);
        
        // Add padding if needed to ensure key is exactly 256 bytes long
        std::vector<uint8_t> key_bytes = shared_secret.toBinary();
        if (key_bytes.size() < 256) {
            std::vector<uint8_t> padded_key(256, 0);
            std::copy(key_bytes.begin(), key_bytes.end(), padded_key.end() - key_bytes.size());
            shared_secret = BigInteger::fromBinary(padded_key);
        }
        
        return shared_secret;
    }
    
    // Increment message counter and check if re-keying is needed
    bool shouldRekey() {
        message_count++;
        
        // Re-key if more than 100 messages or key is older than 1 week and at least 1 message sent
        auto now = std::chrono::system_clock::now();
        auto days = std::chrono::duration_cast<std::chrono::hours>(now - creation_time).count() / 24;
        
        return (message_count > MESSAGE_THRESHOLD || 
                (days >= TIME_THRESHOLD_DAYS && message_count > 0));
    }
    
    // Generate a new key pair for re-keying (Perfect Forward Secrecy)
    void regenerateKeys() {
        // Generate a new random private key
        private_key = BigInteger::generateRandom(256);
        
        // Calculate new public key
        public_key = g.modPow(private_key, p);
        
        // Reset counters
        creation_time = std::chrono::system_clock::now();
        message_count = 0;
    }
    
    // Key visualization for security verification (fingerprint)
    static std::string visualizeKey(const BigInteger& key) {
        // Extract the first 128 bits of SHA1(key) and 160 bits of SHA256(key)
        std::string keyStr = key.toHexString();
        std::string sha1Hash = SHA1::hash(keyStr);
        std::string sha256Hash = SHA256::hash(keyStr);
        
        // Concatenate the first 128 bits (32 hex chars) of SHA1 and first 160 bits (40 hex chars) of SHA256
        std::string fingerprint = sha1Hash.substr(0, 32) + sha256Hash.substr(0, 40);
        
        return fingerprint;
    }
    
    // Generate a visual representation of the key for user verification
    static std::string generateKeyVisualization(const BigInteger& key) {
        // Use SHA-256 to create a unique fingerprint of the key
        std::string keyStr = key.toHexString();
        std::string fingerprint = SHA256::hash(keyStr);
        
        // Format the fingerprint for visualization (groups of 8 characters with dashes)
        std::stringstream vis;
        vis << "Key Fingerprint: " << fingerprint.substr(0, 8) << "-" 
            << fingerprint.substr(8, 8) << "-" 
            << fingerprint.substr(16, 8) << "-" 
            << fingerprint.substr(24, 8);
        
        return vis.str();
    }
    
    // Generate SVG visualization of the key
    static QString generateKeyVisualization(const std::string& fingerprint) {
        // Create a colorful identicon based on the fingerprint
        QString svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"200\" height=\"200\" viewBox=\"0 0 10 10\">";
        
        // Use the fingerprint to generate a unique visual pattern
        int index = 0;
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                if (index < fingerprint.length()) {
                    char hexChar = fingerprint[index++];
                    int value = 0;
                    if (hexChar >= '0' && hexChar <= '9') {
                        value = hexChar - '0';
                    } else if (hexChar >= 'a' && hexChar <= 'f') {
                        value = hexChar - 'a' + 10;
                    } else if (hexChar >= 'A' && hexChar <= 'F') {
                        value = hexChar - 'A' + 10;
                    }
                    
                    // If value is odd, draw a colored square
                    if (value % 2 == 1) {
                        // Generate a color based on the next few characters in the fingerprint
                        std::string colorPart = fingerprint.substr(index % fingerprint.length(), 6);
                        QString color = "#" + QString::fromStdString(colorPart);
                        
                        // Draw the square
                        svg += QString("<rect x=\"%1\" y=\"%2\" width=\"1\" height=\"1\" fill=\"%3\" />")
                                .arg(x)
                                .arg(y)
                                .arg(color);
                        
                        // Mirror the pattern for symmetry
                        if (x < 4) {
                            svg += QString("<rect x=\"%1\" y=\"%2\" width=\"1\" height=\"1\" fill=\"%3\" />")
                                    .arg(9 - x)
                                    .arg(y)
                                    .arg(color);
                        }
                    }
                }
            }
        }
        
        svg += "</svg>";
        return svg;
    }
};


// RSA implementation for signature verification and encryption
// RSA Key Classes
class RSAPublicKey {
private:
    BigInteger n; // modulus
    BigInteger e; // public exponent
public:
    RSAPublicKey() {}
    
    RSAPublicKey(const BigInteger& n, const BigInteger& e) 
        : n(n), e(e) {}
        
    bool verify(const std::string& message, const BigInteger& signature) const {
        // Hash the message
        std::string hash = SHA256::hash(message);
        
        // Verify signature
        BigInteger hashInt(hash);
        BigInteger decrypted = signature.modPow(e, n);
        
        return decrypted == hashInt;
    }
    
    std::string serialize() const {
        return n.toHexString() + ":" + e.toHexString();
    }
    
    static RSAPublicKey deserialize(const std::string& serialized) {
        size_t pos = serialized.find(':');
        if (pos == std::string::npos) {
            throw std::runtime_error("Invalid RSA public key format");
        }
        
        BigInteger n(serialized.substr(0, pos));
        BigInteger e(serialized.substr(pos + 1));
        
        return RSAPublicKey(n, e);
    }
};

class RSAPrivateKey {
private:
    BigInteger n; // modulus
    BigInteger e; // public exponent
    BigInteger d; // private exponent
public:
    RSAPrivateKey() {}
    
    RSAPrivateKey(const BigInteger& n, const BigInteger& e, const BigInteger& d)
        : n(n), e(e), d(d) {}
        
    BigInteger sign(const std::string& message) const {
        if (d.isZero()) {
            throw std::runtime_error("Private key not available for signing");
        }
        
        // Hash the message
        std::string hash = SHA256::hash(message);
        
        // Sign the hash
        BigInteger hashInt(hash);
        return hashInt.modPow(d, n);
    }
    
    RSAPublicKey getPublicKey() const {
        return RSAPublicKey(n, e);
    }
    
    std::string serialize() const {
        return n.toHexString() + ":" + e.toHexString() + ":" + d.toHexString();
    }
    
    static RSAPrivateKey deserialize(const std::string& serialized) {
        size_t pos1 = serialized.find(':');
        if (pos1 == std::string::npos) {
            throw std::runtime_error("Invalid RSA private key format");
        }
        
        size_t pos2 = serialized.find(':', pos1 + 1);
        if (pos2 == std::string::npos) {
            throw std::runtime_error("Invalid RSA private key format");
        }
        
        BigInteger n(serialized.substr(0, pos1));
        BigInteger e(serialized.substr(pos1 + 1, pos2 - pos1 - 1));
        BigInteger d(serialized.substr(pos2 + 1));
        
        return RSAPrivateKey(n, e, d);
    }
};

// Key exchange state structure
struct KeyExchangeState {
    BigInteger localPrivateKey;   // Our private key
    BigInteger localPublicKey;    // Our public key
    BigInteger remotePublicKey;   // Their public key
    std::string nonce;            // For replay protection
    QDateTime initiatedAt;        // When key exchange started
    bool completed = false;       // Whether the exchange is complete
};

class RSA {
protected:
    BigInteger n; // modulus
    BigInteger e; // public exponent
    BigInteger d; // private exponent (only stored on client)

public:
    // Default constructor
    RSA() {}
    
    // Construct with components
    RSA(const BigInteger& n, const BigInteger& e, const BigInteger& d = BigInteger(0))
        : n(n), e(e), d(d) {}
        
    // Generate key visualization from a key
    static std::string generateKeyVisualization(const BigInteger& key) {
        // Use SHA-256 to create a unique fingerprint of the key
        std::string keyStr = key.toHexString();
        std::string fingerprint = SHA256::hash(keyStr);
        return generateKeyVisualization(fingerprint);
    }
    
    // Generate key visualization from a fingerprint
    static std::string generateKeyVisualization(const std::string& fingerprint) {
        // Format the fingerprint for visualization (groups of 4 characters)
        std::stringstream ss;
        for (size_t i = 0; i < fingerprint.length(); i += 4) {
            if (i > 0 && i % 20 == 0) {
                ss << "\n";
            } else if (i > 0) {
                ss << " ";
            }
            if (i + 4 <= fingerprint.length()) {
                ss << fingerprint.substr(i, 4);
            } else {
                ss << fingerprint.substr(i);
            }
        }
        return ss.str();
    }
    
    // Generate an RSA key pair
    static std::pair<RSA, RSA> generateKeyPair(int bits = 2048) {
        // Generate two random prime numbers p and q
        BigInteger p = generatePrime(bits / 2);
        BigInteger q = generatePrime(bits / 2);
        
        // Calculate n = p * q
        BigInteger n = p * q;
        
        // Calculate Euler's totient function: phi(n) = (p-1) * (q-1)
        BigInteger phi = (p - BigInteger(1)) * (q - BigInteger(1));
        
        // Choose e such that 1 < e < phi and gcd(e, phi) = 1
        BigInteger e = BigInteger(65537); // Commonly used value for e
        
        // Calculate d such that (d * e) % phi = 1
        BigInteger d = modInverse(e, phi);
        
        // Create public and private keys
        RSA publicKey(n, e);
        RSA privateKey(n, e, d);
        
        return std::make_pair(publicKey, privateKey);
    }
    
    // Sign a message using private key
    BigInteger sign(const std::string& message) const {
        if (d.isZero()) {
            throw std::runtime_error("Cannot sign with public key");
        }
        
        // Hash the message
        std::string hash = SHA256::hash(message);
        BigInteger hashInt(hash);
        
        // Calculate signature: sign = hash^d mod n
        return hashInt.modPow(d, n);
    }
    
    // Verify a signature using public key
    bool verify(const std::string& message, const BigInteger& signature) const {
        // Hash the message
        std::string hash = SHA256::hash(message);
        BigInteger hashInt(hash);
        
        // Calculate verification: verify = signature^e mod n
        BigInteger verify = signature.modPow(e, n);
        
        // If verify == hashInt, signature is valid
        return verify == hashInt;
    }
    
    // Export public key as string
    std::string exportPublicKey() const {
        std::stringstream ss;
        ss << n.toHexString() << ":" << e.toHexString();
        return ss.str();
    }
    
    // Import public key from string
    static RSA importPublicKey(const std::string& keyStr) {
        size_t pos = keyStr.find(':');
        if (pos == std::string::npos) {
            throw std::runtime_error("Invalid public key format");
        }
        
        BigInteger n(keyStr.substr(0, pos));
        BigInteger e(keyStr.substr(pos + 1));
        
        return RSA(n, e);
    }
    
    // Get modulus
    BigInteger getModulus() const {
        return n;
    }
    
    // Get public exponent
    BigInteger getPublicExponent() const {
        return e;
    }
    
    // Get private exponent
    BigInteger getPrivateExponent() const {
        return d;
    }
    
private:
    // Generate a random prime number of specified bit length
    static BigInteger generatePrime(int bits) {
        // Generate random odd number of specified bit length
        BigInteger p = BigInteger::generateRandom(bits);
        
        // Ensure it's odd
        if (!p.isOdd()) {
            p = p + BigInteger(1);
        }
        
        // Simple primality test
        while (!isPrime(p)) {
            p = p + BigInteger(2); // Next odd number
        }
        
        return p;
    }
    
    // Simple primality test (for demonstration only)
    static bool isPrime(const BigInteger& n) {
        if (n <= BigInteger(1)) return false;
        if (n <= BigInteger(3)) return true;
        if (n.isOdd() == false) return false;
        
        // Check divisibility up to sqrt(n)
        BigInteger i(3);
        while (i * i <= n) {
            BigInteger rem = n;
            BigInteger temp = i;
            
            // Manually calculate n % i without using modulo operator
            while (rem >= temp) {
                BigInteger q = rem / temp;
                rem = rem - (q * temp);
            }
            
            if (rem.isZero()) return false;
            i = i + BigInteger(2);
        }
        
        return true;
    }
    
    // Calculate modular inverse using Extended Euclidean Algorithm
    static BigInteger modInverse(const BigInteger& a_in, const BigInteger& m_in) {
        // Make copies to avoid modifying const arguments
        BigInteger a = a_in;
        BigInteger m = m_in;
        BigInteger m0 = m_in;
        
        if (m == BigInteger(1)) {
            return BigInteger(0);
        }
        
        // Extended Euclidean Algorithm
        BigInteger x0 = BigInteger(0);
        BigInteger x1 = BigInteger(1);
        
        while (a > BigInteger(1)) {
            // Calculate quotient and remainder manually without using % operator
            BigInteger q = a / m;
            BigInteger r = a; // Start with a
            
            // Calculate r = a - q * m (equivalent to a % m)
            BigInteger temp = q * m;
            if (r >= temp) {
                r = r - temp;
            }
            
            // Standard EEA update
            a = m;
            m = r;
            
            // Update coefficients
            BigInteger temp_x = x0;
            x0 = x1 - q * x0;
            x1 = temp_x;
        }
        
        // Make sure x1 is positive
        if (x1 < BigInteger(0)) {
            x1 = x1 + m0;
        }
        
        return x1;
    }
};

class CustomKDF {
public:
    static std::vector<uint8_t> deriveKey(const BigInteger& sharedSecret, const std::string& salt, size_t keyLength) {
        // Convert shared secret to a string
        std::string secretStr = sharedSecret.toHexString();
        
        // Initial hash using SHA-256
        std::string hash = SHA256::hash(secretStr + salt);
        
        // Ensure we have enough bytes for the requested key length
        while (hash.length() < keyLength * 2) { // *2 because each byte is represented by 2 hex chars
            hash += SHA256::hash(hash + secretStr + salt);
        }
        
        // Convert hex string to bytes
        std::vector<uint8_t> key(keyLength);
        for (size_t i = 0; i < keyLength; i++) {
            std::string byteStr = hash.substr(i * 2, 2);
            key[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        }
        
        return key;
    }
};

// Message structure for client-server communication
struct Message {
    enum Type {
        CONNECT,
        DISCONNECT,
        CHAT_MESSAGE,
        KEY_EXCHANGE_REQUEST,
        KEY_EXCHANGE_RESPONSE,
        PROOF_OF_WORK_CHALLENGE,
        PROOF_OF_WORK_RESPONSE,
        CLIENT_LIST_REQUEST,
        CLIENT_LIST_RESPONSE,
        DH_KEY_EXCHANGE_INIT,
        DH_KEY_EXCHANGE_REPLY,
        RSA_PUBLIC_KEY_REQUEST,
        RSA_PUBLIC_KEY_RESPONSE
    };
    
    Type type;
    std::string sender;
    std::string recipient;
    std::string content;
    std::string timestamp;
    std::string nonce; // For replay protection
    
    static std::string serialize(const Message& msg) {
        std::stringstream ss;
        ss << static_cast<int>(msg.type) << '|'
           << msg.sender << '|'
           << msg.recipient << '|'
           << msg.content << '|'
           << msg.timestamp << '|'
           << msg.nonce;
        return ss.str();
    }
    
    static Message deserialize(const std::string& data) {
        Message msg;
        std::stringstream ss(data);
        std::string token;
        
        // Parse type
        std::getline(ss, token, '|');
        msg.type = static_cast<Type>(std::stoi(token));
        
        // Parse sender
        std::getline(ss, msg.sender, '|');
        
        // Parse recipient
        std::getline(ss, msg.recipient, '|');
        
        // Parse content
        std::getline(ss, msg.content, '|');
        
        // Parse timestamp
        std::getline(ss, msg.timestamp, '|');
        
        // Parse nonce (if available)
        if (!ss.eof()) {
            std::getline(ss, msg.nonce);
        }
        
        return msg;
    }
    
    static std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// Proof of Work implementation
class ProofOfWork {
public:
    static std::string solveChallenge(const std::string& challenge, int difficulty) {
        int counter = 0;
        std::string solution;
        
        while (true) {
            solution = std::to_string(counter);
            std::string hash = SHA256::hash(challenge + solution);
            
            // Check if the first 'difficulty' bits are zero
            bool valid = true;
            for (int i = 0; i < difficulty / 4; i++) {
                if (hash[i] != '0') {
                    valid = false;
                    break;
                }
            }
            
            if (valid) {
                return solution;
            }
            
            counter++;
        }
    }
};

// Database Manager for storing messages
class DatabaseManager {
private:
    QSqlDatabase db;
    
public:
    DatabaseManager() {
        // Create the database directory if it doesn't exist
        QDir dir;
        if (!dir.exists("data")) {
            dir.mkdir("data");
        }
        
        db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("data/messages.db");
        
        if (!db.open()) {
            qCritical() << "Failed to open database:" << db.lastError().text();
            return;
        }
        
        // Create tables if they don't exist
        QSqlQuery query;
        
        // Friends table
        query.exec("CREATE TABLE IF NOT EXISTS friends ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                   "username TEXT UNIQUE NOT NULL, "
                   "key_fingerprint TEXT, "
                   "last_message_time TEXT)");
        
        // Messages table
        query.exec("CREATE TABLE IF NOT EXISTS messages ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                   "sender TEXT NOT NULL, "
                   "recipient TEXT NOT NULL, "
                   "content TEXT NOT NULL, "
                   "timestamp TEXT NOT NULL, "
                   "is_sent INTEGER NOT NULL)");
    }
    
    ~DatabaseManager() {
        if (db.isOpen()) {
            db.close();
        }
    }
    
    // Add or update a friend
    bool saveFriend(const QString& username, const QString& keyFingerprint) {
        QSqlQuery query;
        query.prepare("INSERT OR REPLACE INTO friends (username, key_fingerprint) VALUES (?, ?)");
        query.addBindValue(username);
        query.addBindValue(keyFingerprint);
        
        return query.exec();
    }
    
    // Get all friends
    QVector<QPair<QString, QString>> getFriends() {
        QVector<QPair<QString, QString>> friends;
        
        QSqlQuery query("SELECT username, key_fingerprint FROM friends ORDER BY username");
        while (query.next()) {
            QString username = query.value(0).toString();
            QString keyFingerprint = query.value(1).toString();
            friends.append(qMakePair(username, keyFingerprint));
        }
        
        return friends;
    }
    
    // Save a message
    bool saveMessage(const QString& sender, const QString& recipient, const QString& content, const QString& timestamp, bool isSent) {
        QSqlQuery query;
        query.prepare("INSERT INTO messages (sender, recipient, content, timestamp, is_sent) VALUES (?, ?, ?, ?, ?)");
        query.addBindValue(sender);
        query.addBindValue(recipient);
        query.addBindValue(content);
        query.addBindValue(timestamp);
        query.addBindValue(isSent ? 1 : 0);
        
        return query.exec();
    }
    
    // Get messages between two users
    QVector<QVariantMap> getMessages(const QString& user1, const QString& user2) {
        QVector<QVariantMap> messages;
        
        QSqlQuery query;
        query.prepare("SELECT sender, recipient, content, timestamp, is_sent FROM messages "
                     "WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?) "
                     "ORDER BY timestamp");
        query.addBindValue(user1);
        query.addBindValue(user2);
        query.addBindValue(user2);
        query.addBindValue(user1);
        
        if (query.exec()) {
            while (query.next()) {
                QVariantMap message;
                message["sender"] = query.value(0).toString();
                message["recipient"] = query.value(1).toString();
                message["content"] = query.value(2).toString();
                message["timestamp"] = query.value(3).toString();
                message["is_sent"] = query.value(4).toBool();
                messages.append(message);
            }
        }
        
        return messages;
    }
    
    // Update last message time for a friend
    bool updateLastMessageTime(const QString& username, const QString& timestamp) {
        QSqlQuery query;
        query.prepare("UPDATE friends SET last_message_time = ? WHERE username = ?");
        query.addBindValue(timestamp);
        query.addBindValue(username);
        
        return query.exec();
    }
};

// Socket wrapper for client-server communication
class SocketWrapper : public QObject {
    Q_OBJECT
    
private:
    int socket;
    std::thread receiveThread;
    bool connected;
    std::mutex sendMutex;
    
public:
    SocketWrapper(QObject* parent = nullptr) : QObject(parent), socket(-1), connected(false) {}
    
    ~SocketWrapper() {
        disconnect();
    }
    
    bool connect(const std::string& hostname, int port) {
        // Create socket
        socket = ::socket(AF_INET, SOCK_STREAM, 0);
        if (socket == -1) {
            emit error("Failed to create socket");
            return false;
        }
        
        // Set up server address
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, hostname.c_str(), &serverAddr.sin_addr) <= 0) {
            emit error("Invalid address");
            close(socket);
            socket = -1;
            return false;
        }
        
        // Connect to server
        if (::connect(socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            emit error("Connection failed");
            close(socket);
            socket = -1;
            return false;
        }
        
        connected = true;
        
        // Start receive thread
        receiveThread = std::thread(&SocketWrapper::receiveLoop, this);
        
        return true;
    }
    
    void disconnect() {
        if (connected) {
            connected = false;
            
            if (socket != -1) {
                close(socket);
                socket = -1;
            }
            
            if (receiveThread.joinable()) {
                receiveThread.join();
            }
        }
    }
    
    bool isConnected() const {
        return connected;
    }
    
    bool sendMessage(const Message& msg) {
        if (!connected) {
            return false;
        }
        
        std::string data = Message::serialize(msg);
        return sendMessage(data);
    }
    
    bool sendMessage(const std::string& data) {
        if (!connected) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(sendMutex);
        ssize_t bytesSent = send(socket, data.c_str(), data.length(), 0);
        
        return bytesSent == static_cast<ssize_t>(data.length());
    }
    
private:
    void receiveLoop() {
        char buffer[4096];
        
        while (connected) {
            memset(buffer, 0, sizeof(buffer));
            ssize_t bytesRead = recv(socket, buffer, sizeof(buffer) - 1, 0);
            
            if (bytesRead > 0) {
                try {
                    Message msg = Message::deserialize(std::string(buffer, bytesRead));
                    emit messageReceived(msg);
                } catch (const std::exception& e) {
                    emit error(std::string("Failed to parse message: ") + e.what());
                }
            } else if (bytesRead == 0) {
                // Connection closed by server
                connected = false;
                emit disconnected();
                break;
            } else {
                // Error
                connected = false;
                emit error("Connection error");
                break;
            }
        }
    }
    
signals:
    void messageReceived(const Message& msg);
    void disconnected();
    void error(const std::string& errorMsg);
};

// Chat message widget for displaying chat messages
class ChatBubbleWidget : public QWidget {
    Q_OBJECT
    
private:
    QString sender;
    QString message;
    QString timestamp;
    bool isSent;
    
public:
    ChatBubbleWidget(const QString& sender, const QString& message, const QString& timestamp, bool isSent, QWidget* parent = nullptr)
        : QWidget(parent), sender(sender), message(message), timestamp(timestamp), isSent(isSent) {
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
        setMinimumHeight(50);
    }
    
    QSize sizeHint() const override {
        QFontMetrics fm(font());
        int width = fm.horizontalAdvance(message) + 40; // Add padding
        int height = fm.height() * (message.count('\n') + 1) + 40; // Add padding
        
        return QSize(width, height);
    }
    
protected:
    void paintEvent(QPaintEvent* event) override {
        Q_UNUSED(event);
        
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        
        QFont nameFont = font();
        nameFont.setBold(true);
        
        QFont messageFont = font();
        
        QFont timeFont = font();
        timeFont.setPointSize(timeFont.pointSize() - 2);
        
        QFontMetrics nameFm(nameFont);
        QFontMetrics messageFm(messageFont);
        QFontMetrics timeFm(timeFont);
        
        // Calculate text dimensions
        int nameWidth = nameFm.horizontalAdvance(sender);
        int messageWidth = messageFm.horizontalAdvance(message);
        int timeWidth = timeFm.horizontalAdvance(timestamp);
        
        int bubbleWidth = qMax(nameWidth, qMax(messageWidth, timeWidth)) + 20; // Add padding
        int bubbleHeight = nameFm.height() + messageFm.height() * (message.count('\n') + 1) + timeFm.height() + 20; // Add padding
        
        // Calculate bubble position
        int bubbleX = isSent ? width() - bubbleWidth - 10 : 10;
        int bubbleY = 10;
        
        // Draw bubble background
        QColor bgColor = isSent ? QColor(79, 195, 247) : QColor(220, 220, 220);
        painter.setBrush(bgColor);
        painter.setPen(Qt::NoPen);
        
        QRectF bubbleRect(bubbleX, bubbleY, bubbleWidth, bubbleHeight);
        painter.drawRoundedRect(bubbleRect, 10, 10);
        
        // Draw sender name
        painter.setFont(nameFont);
        painter.setPen(Qt::black);
        QRectF nameRect(bubbleX + 10, bubbleY + 5, bubbleWidth - 20, nameFm.height());
        painter.drawText(nameRect, Qt::AlignLeft | Qt::AlignTop, sender);
        
        // Draw message text
        painter.setFont(messageFont);
        QRectF messageRect(bubbleX + 10, bubbleY + nameFm.height() + 5, bubbleWidth - 20, messageFm.height() * (message.count('\n') + 1));
        painter.drawText(messageRect, Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, message);
        
        // Draw timestamp
        painter.setFont(timeFont);
        painter.setPen(Qt::darkGray);
        QRectF timeRect(bubbleX + 10, bubbleY + nameFm.height() + messageFm.height() * (message.count('\n') + 1) + 5, bubbleWidth - 20, timeFm.height());
        painter.drawText(timeRect, Qt::AlignRight | Qt::AlignBottom, timestamp);
    }
};

// Key visualization dialog
class KeyVisualizationDialog : public QDialog {
    Q_OBJECT
    
private:
    QSvgWidget* svgWidget;
    QLabel* keyFingerprintLabel;
    QString fingerprint;
    
public:
    KeyVisualizationDialog(const QString& keyFingerprint, QWidget* parent = nullptr)
        : QDialog(parent), fingerprint(keyFingerprint) {
        setWindowTitle("Key Visualization");
        setMinimumSize(300, 350);
        
        QVBoxLayout* layout = new QVBoxLayout(this);
        
        // Create SVG widget
        svgWidget = new QSvgWidget(this);
        svgWidget->setMinimumSize(200, 200);
        
        // Generate SVG visualization from key fingerprint
        QString svg = DiffieHellman::generateKeyVisualization(fingerprint.toStdString());
        QByteArray svgData = svg.toUtf8();
        svgWidget->load(svgData);
        
        // Create fingerprint label
        keyFingerprintLabel = new QLabel(this);
        keyFingerprintLabel->setText("Key Fingerprint:\n" + fingerprint);
        keyFingerprintLabel->setAlignment(Qt::AlignCenter);
        keyFingerprintLabel->setWordWrap(true);
        
        QLabel* instructions = new QLabel(this);
        instructions->setText("Compare this image with your friend's to verify the secure connection.\n"
                             "If the images match, your chat is secure.");
        instructions->setAlignment(Qt::AlignCenter);
        instructions->setWordWrap(true);
        
        QPushButton* closeButton = new QPushButton("Close", this);
        connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
        
        layout->addWidget(svgWidget);
        layout->addWidget(keyFingerprintLabel);
        layout->addWidget(instructions);
        layout->addWidget(closeButton);
    }
};

// Main chat client
class ChatClient : public QMainWindow {
    Q_OBJECT
    
private:
    // UI elements
    QWidget* centralWidget;
    QListWidget* friendsList;
    QWidget* chatWidget;
    QScrollArea* chatScrollArea;
    QVBoxLayout* chatLayout;
    QLineEdit* messageInput;
    QPushButton* sendButton;
    QLabel* connectionStatus;
    QToolBar* toolBar;
    QStatusBar* statusBar;
    
    // Client data
    QString username;
    QString currentChatPartner;
    SocketWrapper* socket;
    DatabaseManager* dbManager;
    std::map<QString, BigInteger> sharedSecrets;
    std::map<QString, std::string> keyFingerprints;
    std::map<QString, QDateTime> keyCreationTimes;
    int messageCounter;
    
    // Security data
    std::map<std::string, BigInteger> encryptionKeys;
    std::map<std::string, KeyExchangeState> peerKeyExchangeState;
    std::map<std::string, Message> pendingKeyExchanges;
    std::map<std::string, RSAPublicKey> peerRsaPublicKeys;
    RSAPrivateKey rsaPrivateKey;
    BigInteger peerPublicKey;
    
    // Diffie-Hellman parameters
    const std::string dhPrime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
                                "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                                "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD96"
                                "1C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE5"
                                "15D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    
public:
    ChatClient(QWidget* parent = nullptr) : QMainWindow(parent), messageCounter(0) {
        setWindowTitle("Secure Chat");
        setMinimumSize(800, 600);
        
        // Initialize database
        dbManager = new DatabaseManager();
        
        // Initialize socket
        socket = new SocketWrapper(this);
        connect(socket, &SocketWrapper::messageReceived, this, &ChatClient::handleMessage);
        connect(socket, &SocketWrapper::disconnected, this, &ChatClient::handleDisconnect);
        // We'll connect socket error handler differently - needs QString parameter type matching
        connect(socket, SIGNAL(error(QString)), this, SLOT(handleSocketError(QString)));
        
        // Set up UI
        setupUI();
        
        // Show login dialog at startup
        QTimer::singleShot(0, this, &ChatClient::showLoginDialog);
    }
    
    // Forward declaration of handlers
    void handleChatMessage(const Message& msg);
    void handleKeyExchangeRequest(const Message& msg);
    void handleKeyExchangeResponse(const Message& msg);
    void handleProofOfWorkChallenge(const Message& msg);
    void handleClientList(const Message& msg);
    void handleKeyExchangeInit(const Message& msg);
    void handleKeyExchangeReply(const Message& msg);
    void handleRsaPublicKey(const Message& msg);
    
    // Handle socket disconnection
    void handleDisconnect() {
        connected = false;
        ui->statusBar->showMessage("Disconnected from server", 3000);
        ui->actionConnect->setEnabled(true);
        ui->actionDisconnect->setEnabled(false);
    }
    
    // Handle socket errors
    void handleSocketError(const QString& errorMsg) {
        QMessageBox::critical(this, "Connection Error", errorMsg);
        ui->actionConnect->setEnabled(true);
        ui->actionDisconnect->setEnabled(false);
    }
    
    // Forward declaration of helper methods
    void updateChatSecurityStatus(bool isSecure);
    std::string generateNonce();
    void showKeyVisualization(const BigInteger& sharedSecret);
    void showKeyVisualization(const QString& fingerprint);
    
    ~ChatClient() {
        if (socket) {
            socket->disconnect();
            delete socket;
        }
        
        if (dbManager) {
            delete dbManager;
        }
    }
    
private:
    void setupUI() {
        centralWidget = new QWidget(this);
        setCentralWidget(centralWidget);
        
        QHBoxLayout* mainLayout = new QHBoxLayout(centralWidget);
        
        // Friends list section
        QVBoxLayout* friendsLayout = new QVBoxLayout();
        QLabel* friendsLabel = new QLabel("Friends", this);
        friendsLabel->setAlignment(Qt::AlignCenter);
        friendsLabel->setStyleSheet("font-weight: bold; font-size: 16px;");
        
        friendsList = new QListWidget(this);
        friendsList->setMinimumWidth(200);
        connect(friendsList, &QListWidget::itemClicked, this, &ChatClient::onFriendSelected);
        
        QPushButton* addFriendButton = new QPushButton("Add Friend", this);
        connect(addFriendButton, &QPushButton::clicked, this, &ChatClient::showAddFriendDialog);
        
        friendsLayout->addWidget(friendsLabel);
        friendsLayout->addWidget(friendsList);
        friendsLayout->addWidget(addFriendButton);
        
        // Chat section
        QVBoxLayout* chatContainerLayout = new QVBoxLayout();
        
        chatWidget = new QWidget(this);
        chatWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        
        chatScrollArea = new QScrollArea(this);
        chatScrollArea->setWidgetResizable(true);
        chatScrollArea->setWidget(chatWidget);
        chatScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chatScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        
        chatLayout = new QVBoxLayout(chatWidget);
        chatLayout->setAlignment(Qt::AlignTop);
        chatLayout->setSpacing(10);
        
        QHBoxLayout* inputLayout = new QHBoxLayout();
        messageInput = new QLineEdit(this);
        messageInput->setPlaceholderText("Type your message here...");
        connect(messageInput, &QLineEdit::returnPressed, this, &ChatClient::sendMessage);
        
        sendButton = new QPushButton("Send", this);
        connect(sendButton, &QPushButton::clicked, this, &ChatClient::sendMessage);
        
        inputLayout->addWidget(messageInput);
        inputLayout->addWidget(sendButton);
        
        chatContainerLayout->addWidget(chatScrollArea);
        chatContainerLayout->addLayout(inputLayout);
        
        mainLayout->addLayout(friendsLayout, 1);
        mainLayout->addLayout(chatContainerLayout, 3);
        
        // Status bar
        QStatusBar* statusBar = new QStatusBar(this);
        setStatusBar(statusBar);
        
        connectionStatus = new QLabel("Not Connected", this);
        statusBar->addPermanentWidget(connectionStatus);
        
        // Toolbar
        toolBar = new QToolBar("Main Toolbar", this);
        addToolBar(toolBar);
        
        QAction* connectAction = new QAction("Connect", this);
        QAction* disconnectAction = new QAction("Disconnect", this);
        QAction* viewKeyAction = new QAction("View Key", this);
        QAction* refreshAction = new QAction("Refresh Friends", this);
        
        connect(connectAction, &QAction::triggered, this, &ChatClient::showConnectDialog);
        connect(disconnectAction, &QAction::triggered, this, &ChatClient::disconnect);
        connect(viewKeyAction, &QAction::triggered, this, &ChatClient::showCurrentKeyVisualization);
        connect(refreshAction, &QAction::triggered, this, &ChatClient::requestClientList);
        
        toolBar->addAction(connectAction);
        toolBar->addAction(disconnectAction);
        toolBar->addAction(viewKeyAction);
        toolBar->addAction(refreshAction);
        
        // Disable chat inputs initially
        messageInput->setEnabled(false);
        sendButton->setEnabled(false);
    }
    
    void showLoginDialog() {
        QDialog dialog(this);
        dialog.setWindowTitle("Login");
        dialog.setMinimumWidth(300);
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        QLabel* label = new QLabel("Enter your username:", &dialog);
        QLineEdit* usernameInput = new QLineEdit(&dialog);
        
        QPushButton* okButton = new QPushButton("OK", &dialog);
        connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        
        layout->addWidget(label);
        layout->addWidget(usernameInput);
        layout->addWidget(okButton);
        
        if (dialog.exec() == QDialog::Accepted) {
            username = usernameInput->text().trimmed();
            if (username.isEmpty()) {
                username = "User_" + QString::number(QDateTime::currentMSecsSinceEpoch() % 10000);
            }
            
            setWindowTitle("Secure Chat - " + username);
            showConnectDialog();
        } else {
            QApplication::quit();
        }
    }
    
    void showConnectDialog() {
        QDialog dialog(this);
        dialog.setWindowTitle("Connect to Server");
        dialog.setMinimumWidth(300);
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        QLabel* hostLabel = new QLabel("Server address:", &dialog);
        QLineEdit* hostInput = new QLineEdit("127.0.0.1", &dialog);
        
        QLabel* portLabel = new QLabel("Port:", &dialog);
        QLineEdit* portInput = new QLineEdit("8000", &dialog);
        
        QPushButton* connectButton = new QPushButton("Connect", &dialog);
        connect(connectButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        
        layout->addWidget(hostLabel);
        layout->addWidget(hostInput);
        layout->addWidget(portLabel);
        layout->addWidget(portInput);
        layout->addWidget(connectButton);
        
        if (dialog.exec() == QDialog::Accepted) {
            QString host = hostInput->text().trimmed();
            int port = portInput->text().toInt();
            
            connectToServer(host, port);
        }
    }
    
    void showAddFriendDialog() {
        QDialog dialog(this);
        dialog.setWindowTitle("Add Friend");
        dialog.setMinimumWidth(300);
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        QLabel* label = new QLabel("Enter friend's username:", &dialog);
        QLineEdit* friendInput = new QLineEdit(&dialog);
        
        QPushButton* addButton = new QPushButton("Add", &dialog);
        connect(addButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        
        layout->addWidget(label);
        layout->addWidget(friendInput);
        layout->addWidget(addButton);
        
        if (dialog.exec() == QDialog::Accepted) {
            QString friendName = friendInput->text().trimmed();
            if (!friendName.isEmpty() && friendName != username) {
                // Add friend locally
                dbManager->saveFriend(friendName, "");
                
                // Initiate key exchange
                initiateKeyExchange(friendName);
                
                // Update UI
                loadFriendsList();
            }
        }
    }
    
    void connectToServer(const QString& host, int port) {
        if (socket->connect(host.toStdString(), port)) {
            // Handle proof of work challenge first
            // The actual connection logic continues in the handleMessage function
            // when we receive the challenge
            connectionStatus->setText("Connecting...");
        } else {
            QMessageBox::critical(this, "Connection Error", "Failed to connect to server");
        }
    }
    
    void disconnect() {
        if (socket->isConnected()) {
            // Send disconnect message
            Message msg;
            msg.type = Message::DISCONNECT;
            msg.sender = username.toStdString();
            msg.timestamp = Message::getCurrentTimestamp();
            socket->sendMessage(msg);
            
            // Disconnect socket
            socket->disconnect();
            
            // Update UI
            connectionStatus->setText("Not Connected");
            messageInput->setEnabled(false);
            sendButton->setEnabled(false);
        }
    }
    
    void loadFriendsList() {
        friendsList->clear();
        
        QVector<QPair<QString, QString>> friends = dbManager->getFriends();
        for (const auto& friend_ : friends) {
            QListWidgetItem* item = new QListWidgetItem(friend_.first);
            friendsList->addItem(item);
        }
    }
    
    void loadChatHistory(const QString& partner) {
        // Clear current chat
        while (QLayoutItem* item = chatLayout->takeAt(0)) {
            if (QWidget* widget = item->widget()) {
                widget->deleteLater();
            }
            delete item;
        }
        
        // Load message history
        QVector<QVariantMap> messages = dbManager->getMessages(username, partner);
        for (const QVariantMap& msg : messages) {
            QString sender = msg["sender"].toString();
            QString content = msg["content"].toString();
            QString timestamp = msg["timestamp"].toString();
            bool isSent = sender == username;
            
            addChatMessage(sender, content, timestamp, isSent);
        }
        
        // Scroll to bottom
        QTimer::singleShot(0, this, [this]() {
            chatScrollArea->verticalScrollBar()->setValue(
                chatScrollArea->verticalScrollBar()->maximum());
        });
    }
    
    void addChatMessage(const QString& sender, const QString& message, const QString& timestamp, bool isSent) {
        ChatBubbleWidget* bubble = new ChatBubbleWidget(sender, message, timestamp, isSent);
        chatLayout->addWidget(bubble);
        
        // Scroll to bottom
        QTimer::singleShot(0, this, [this]() {
            chatScrollArea->verticalScrollBar()->setValue(
                chatScrollArea->verticalScrollBar()->maximum());
        });
    }
    
    void onFriendSelected(QListWidgetItem* item) {
        if (item) {
            currentChatPartner = item->text();
            loadChatHistory(currentChatPartner);
            
            // Enable chat inputs
            messageInput->setEnabled(true);
            sendButton->setEnabled(true);
            
            // Check if we need to initiate key exchange
            if (!sharedSecrets.count(currentChatPartner)) {
                initiateKeyExchange(currentChatPartner);
            } else {
                // Check if key needs refresh (older than 1 week and at least 1 message sent)
                QDateTime keyCreationTime = keyCreationTimes[currentChatPartner];
                if (keyCreationTime.daysTo(QDateTime::currentDateTime()) >= 7 && messageCounter >= 1) {
                    initiateKeyExchange(currentChatPartner);
                }
                // Also check if more than 100 messages have been exchanged
                else if (messageCounter >= 100) {
                    initiateKeyExchange(currentChatPartner);
                }
            }
        }
    }
    
    // Utility methods for security
    std::string generateNonce() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
        
        std::stringstream ss;
        for (int i = 0; i < 4; i++) {
            ss << std::hex << std::setw(8) << std::setfill('0') << dis(gen);
        }
        return ss.str();
    }
    
    void logError(const QString& message) {
        qDebug() << "ERROR: " << message;
        statusBar->showMessage("Error: " + message, 5000);
    }
    
    void updateChatSecurityStatus(bool secure) {
        if (secure) {
            statusBar->showMessage("Secure chat established", 3000);
            // Update UI to show secure status
        } else {
            statusBar->showMessage("Insecure chat", 3000);
            // Update UI to show insecure status
        }
    }
    
    void showKeyVisualization(const BigInteger& sharedSecret) {
        // Convert BigInteger to fingerprint
        QString fingerprint = QString::fromStdString(DiffieHellman::generateKeyVisualization(sharedSecret));
        showKeyVisualization(fingerprint);
    }
    
    void showKeyVisualization(const QString& fingerprint) {
        KeyVisualizationDialog* dialog = new KeyVisualizationDialog(fingerprint, this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    }
    
    // Method to start a key exchange with another client
    void initiateKeyExchange(const QString& partner) {
        if (partner.isEmpty() || !socket->isConnected()) {
            return;
        }
        
        // Create a new DiffieHellman instance
        DiffieHellman dh(dhPrime);
        BigInteger privateKey = dh.generatePrivateKey();
        BigInteger publicKey = dh.generatePublicKey(privateKey);
        
        // Sign the public key with our RSA private key
        BigInteger signature = rsaPrivateKey.sign(publicKey.toHexString());
        
        // Create and send the key exchange initiation message
        Message msg;
        msg.type = Message::DH_KEY_EXCHANGE_INIT;
        msg.sender = username.toStdString();
        msg.recipient = partner.toStdString();
        msg.content = publicKey.toHexString() + ":" + signature.toHexString();
        msg.timestamp = QDateTime::currentDateTime().toString(Qt::ISODate).toStdString();
        msg.nonce = generateNonce();
        
        // Store the key exchange state
        KeyExchangeState state;
        state.localPrivateKey = privateKey;
        state.localPublicKey = publicKey;
        state.remotePublicKey = BigInteger(0);
        state.nonce = msg.nonce;
        state.initiatedAt = QDateTime::currentDateTime();
        state.completed = false;
        peerKeyExchangeState[partner.toStdString()] = state;
        
        socket->sendMessage(Message::serialize(msg));
        statusBar->showMessage("Key exchange initiated with " + partner, 3000);
    }
    
    void showCurrentKeyVisualization() {
        if (currentChatPartner.isEmpty()) {
            QMessageBox::information(this, "No Active Chat", "Please select a chat partner first.");
            return;
        }
        
        auto it = sharedSecrets.find(currentChatPartner);
        if (it == sharedSecrets.end()) {
            QMessageBox::warning(this, "No Secure Channel", 
                                "No secure channel established with " + currentChatPartner + ". Please wait for key exchange.");
            return;
        }
        
        showKeyVisualization(it->second);
    }
    
    void requestRsaPublicKey(const std::string& username) {
        Message request;
        request.type = Message::RSA_PUBLIC_KEY_REQUEST;
        request.sender = this->username.toStdString();
        request.recipient = username;
        socket->sendMessage(Message::serialize(request));
    }
    
    void sendMessage() {
        if (currentChatPartner.isEmpty() || !socket->isConnected()) {
            return;
        }
        
        QString content = messageInput->text().trimmed();
        if (content.isEmpty()) {
            return;
        }
        
        // Check if we have a shared secret for this partner
        if (sharedSecrets.find(currentChatPartner) == sharedSecrets.end()) {
            QMessageBox::warning(this, "No Secure Channel", 
                                "No secure channel established with " + currentChatPartner + ". Please wait for key exchange.");
            return;
        }
        
        // Send the message
        Message msg;
        msg.type = Message::CHAT_MESSAGE;
        msg.sender = username.toStdString();
        msg.recipient = currentChatPartner.toStdString();
        msg.content = content.toStdString();
        msg.timestamp = Message::getCurrentTimestamp();
        
        if (socket->sendMessage(msg)) {
            // Add to local chat
            addChatMessage(username, content, QString::fromStdString(msg.timestamp), true);
            
            // Save to database
            dbManager->saveMessage(username, currentChatPartner, content, QString::fromStdString(msg.timestamp), true);
            dbManager->updateLastMessageTime(currentChatPartner, QString::fromStdString(msg.timestamp));
            
            // Clear input
            messageInput->clear();
            
            // Increment message counter for perfect forward secrecy
            messageCounter++;
            
            // Check if key needs refresh (more than 100 messages)
            if (messageCounter >= 100) {
                initiateKeyExchange(currentChatPartner);
                messageCounter = 0;
            }
        } else {
            QMessageBox::warning(this, "Send Error", "Failed to send message");
        }
    }
    
    // Function to handle key exchange response
    // This is an empty placeholder to be implemented later
    void logError(const QString& message) {
        qDebug() << "ERROR: " << message;
    }
    
    // Handle Diffie-Hellman key exchange initialization from remote client
    void handleKeyExchangeInit(const Message& msg) {
        // Parse the message content: publicKey|signature
        std::string content = msg.content;
        size_t separatorPos = content.find('|');
        if (separatorPos == std::string::npos) {
            logError("Invalid key exchange format");
            return;
        }
        
        std::string peerPublicKeyStr = content.substr(0, separatorPos);
        std::string signatureStr = content.substr(separatorPos + 1);
        
        BigInteger peerPublicKey(peerPublicKeyStr);
        BigInteger signature(signatureStr);
        
        // Get peer's RSA public key
        auto it = peerRsaPublicKeys.find(msg.sender);
        if (it == peerRsaPublicKeys.end()) {
            // We don't have peer's public key yet, request it
            requestRsaPublicKey(msg.sender);
            
            // Store the message to process later when we have the key
            pendingKeyExchanges[msg.sender] = msg;
            return;
        }
        
        // Verify the signature
        RSA peerRsaKey = it->second;
        if (!peerRsaKey.verify(peerPublicKeyStr, signature)) {
            logError("Invalid signature in key exchange");
            return;
        }
        
        // Create our DH instance
        DiffieHellman dh(DH_PRIME);
        BigInteger ourPublicKey = dh.getPublicKey();
        
        // Calculate shared secret
        BigInteger sharedSecret;
        try {
            sharedSecret = dh.computeSharedSecret(peerPublicKey);
        } catch (const std::exception& e) {
            logError("Error computing shared secret: " + QString(e.what()));
            return;
        }
        
        // Sign our public key
        BigInteger ourSignature = rsaPrivateKey.sign(ourPublicKey.toHexString());
        
        // Prepare response content: publicKey|signature
        std::string responseContent = ourPublicKey.toHexString() + "|" + ourSignature.toHexString();
        
        // Send key exchange response
        Message response;
        response.type = Message::DH_KEY_EXCHANGE_REPLY;
        response.sender = username.toStdString();
        response.recipient = msg.sender;
        response.content = responseContent;
        response.timestamp = Message::getCurrentTimestamp();
        response.nonce = generateNonce();
        
        if (socket->sendMessage(response)) {
            // Store the key exchange state
            peerKeyExchangeState[msg.sender] = {
                dh,                    // DH object
                std::chrono::system_clock::now(),  // creation time
                true,                  // key exchange completed
                peerPublicKey,         // peer's DH public key
                sharedSecret           // shared secret
            };
            
            // Derive the encryption key using KDF
            std::string salt = msg.sender + username.toStdString();
            std::vector<uint8_t> key = CustomKDF::deriveKey(sharedSecret, salt, 32);
            
            // Store the key for this peer
            encryptionKeys[msg.sender] = key;
            
            // Update the UI to show the secure status
            QString peer = QString::fromStdString(msg.sender);
            if (peer == currentChatPartner) {
                updateChatSecurityStatus(true);
                showKeyVisualization(sharedSecret);
            }
            
            ui->statusBar->showMessage("Secure key exchange completed with " + peer, 3000);
        }
    }
    
    // Handle Diffie-Hellman key exchange reply from remote client
    void handleKeyExchangeReply(const Message& msg) {
        // Check if we have an ongoing key exchange with this peer
        auto stateIt = peerKeyExchangeState.find(msg.sender);
        if (stateIt == peerKeyExchangeState.end() || stateIt->second.completed) {
            logError("Unexpected key exchange response");
            return;
        }
        
        // Parse the message content: publicKey|signature
        std::string content = msg.content;
        size_t separatorPos = content.find('|');
        if (separatorPos == std::string::npos) {
            logError("Invalid key exchange format");
            return;
        }
        
        std::string peerPublicKeyStr = content.substr(0, separatorPos);
        std::string signatureStr = content.substr(separatorPos + 1);
        
        BigInteger peerPublicKey(peerPublicKeyStr);
        BigInteger signature(signatureStr);
        
        // Get peer's RSA public key
        auto it = peerRsaPublicKeys.find(msg.sender);
        if (it == peerRsaPublicKeys.end()) {
            // We don't have peer's public key yet, this shouldn't happen
            logError("Missing RSA public key for peer");
            return;
        }
        
        // Verify the signature
        RSA peerRsaKey = it->second;
        if (!peerRsaKey.verify(peerPublicKeyStr, signature)) {
            logError("Invalid signature in key exchange");
            return;
        }
        
        // Calculate shared secret using our stored DH instance
        BigInteger sharedSecret;
        try {
            sharedSecret = stateIt->second.dh.computeSharedSecret(peerPublicKey);
        } catch (const std::exception& e) {
            logError("Error computing shared secret: " + QString(e.what()));
            return;
        }
        
        // Update the key exchange state
        stateIt->second.completed = true;
        stateIt->second.peerPublicKey = peerPublicKey;
        stateIt->second.sharedSecret = sharedSecret;
        
        // Derive the encryption key using KDF
        std::string salt = msg.sender + username.toStdString();
        std::vector<uint8_t> key = CustomKDF::deriveKey(sharedSecret, salt, 32);
        
        // Store the key for this peer
        encryptionKeys[msg.sender] = key;
        
        // Update the UI to show the secure status
        QString peer = QString::fromStdString(msg.sender);
        if (peer == currentChatPartner) {
            updateChatSecurityStatus(true);
            showKeyVisualization(sharedSecret);
        }
        
        ui->statusBar->showMessage("Secure key exchange completed with " + peer, 3000);
    }
    
    void handleKeyExchangeRequest(const Message& msg) {
        QString sender = QString::fromStdString(msg.sender);
        
        // Create DH instance with the specified parameters
        DiffieHellman dh(dhPrime);
        
        // Get our public key
        BigInteger publicKey = dh.getPublicKey();
        
        // Compute shared secret using the other party's public key
        BigInteger otherPublicKey(msg.content);
        BigInteger sharedSecret = dh.computeSharedSecret(otherPublicKey);
        
        // Derive a 256-bit key using our custom KDF
        std::string salt = username.toStdString() + msg.sender;
        std::vector<uint8_t> derivedKey = CustomKDF::deriveKey(sharedSecret, salt, 32);
        
        // Compute key fingerprint for visualization
        std::string fingerprint = DiffieHellman::visualizeKey(sharedSecret);
        
        // Store the shared secret and fingerprint
        sharedSecrets[sender] = sharedSecret;
        keyFingerprints[sender] = fingerprint;
        keyCreationTimes[sender] = QDateTime::currentDateTime();
        
        // Send key exchange response
        Message response;
        response.type = Message::KEY_EXCHANGE_RESPONSE;
        response.sender = username.toStdString();
        response.recipient = msg.sender;
        response.content = publicKey.toHexString();
        response.timestamp = Message::getCurrentTimestamp();
        
        socket->sendMessage(response);
        
        // Save friend with key fingerprint
        dbManager->saveFriend(sender, QString::fromStdString(fingerprint));
        
        // Show key visualization if this is the current chat partner
        if (sender == currentChatPartner) {
            QTimer::singleShot(0, this, [this, fingerprint]() {
                showKeyVisualization(QString::fromStdString(fingerprint));
            });
        }
    }
    
    void handleKeyExchangeResponse(const Message& msg) {
        QString sender = QString::fromStdString(msg.sender);
        
        // Get the DH instance for this exchange
        static std::map<QString, DiffieHellman> dhInstances;
        if (dhInstances.find(sender) == dhInstances.end()) {
            return;
        }
        
        DiffieHellman& dh = dhInstances[sender];
        
        // Compute shared secret using the other party's public key
        BigInteger otherPublicKey(msg.content);
        BigInteger sharedSecret = dh.computeSharedSecret(otherPublicKey);
        
        // Derive a 256-bit key using our custom KDF
        std::string salt = username.toStdString() + msg.sender;
        std::vector<uint8_t> derivedKey = CustomKDF::deriveKey(sharedSecret, salt, 32);
        
        // Compute key fingerprint for visualization
        std::string fingerprint = DiffieHellman::visualizeKey(sharedSecret);
        
        // Store the shared secret and fingerprint
        sharedSecrets[sender] = sharedSecret;
        keyFingerprints[sender] = fingerprint;
        keyCreationTimes[sender] = QDateTime::currentDateTime();
        
        // Save friend with key fingerprint
        dbManager->saveFriend(sender, QString::fromStdString(fingerprint));
        
        // Show key visualization if this is the current chat partner
        if (sender == currentChatPartner) {
            QTimer::singleShot(0, this, [this, fingerprint]() {
                showKeyVisualization(QString::fromStdString(fingerprint));
            });
        }
        
        // Clean up
        dhInstances.erase(sender);
    }
    
    // Implementation of key visualization will be done in a separate PR
    
    // Forward declaration for showing key visualization
    void showCurrentKeyVisualization();
    
    void requestClientList() {
        if (!socket->isConnected()) {
            return;
        }
        
        Message msg;
        msg.type = Message::CLIENT_LIST_REQUEST;
        msg.sender = username.toStdString();
        msg.timestamp = Message::getCurrentTimestamp();
        
        socket->sendMessage(msg);
    }
    
    void handleClientList(const Message& msg) {
        std::string clientListStr = msg.content;
        QStringList clients = QString::fromStdString(clientListStr).split(",");
        
        for (const QString& client : clients) {
            if (client != username && client.length() > 0) {
                // Add to database if not exists
                dbManager->saveFriend(client, "");
            }
        }
        
        // Update UI
        loadFriendsList();
    }
    
public slots:
    void handleMessage(const Message& msg) {
        switch (msg.type) {
            case Message::CHAT_MESSAGE:
                handleChatMessage(msg);
                break;
                
            case Message::KEY_EXCHANGE_REQUEST:
                handleKeyExchangeRequest(msg);
                break;
                
            case Message::KEY_EXCHANGE_RESPONSE:
                handleKeyExchangeResponse(msg);
                break;
                
            case Message::PROOF_OF_WORK_CHALLENGE:
                handleProofOfWorkChallenge(msg);
                break;
                
            case Message::CLIENT_LIST_RESPONSE:
                handleClientList(msg);
                break;
                
            case Message::DH_KEY_EXCHANGE_INIT:
                handleKeyExchangeInit(msg);
                break;
                
            case Message::DH_KEY_EXCHANGE_REPLY:
                handleKeyExchangeReply(msg);
                break;
                
            case Message::RSA_PUBLIC_KEY_RESPONSE:
                handleRsaPublicKey(msg);
                break;
                
            default:
                qDebug() << "Unknown message type received: " << static_cast<int>(msg.type);
                break;
        }
    }
    
    void handleChatMessage(const Message& msg) {
        QString sender = QString::fromStdString(msg.sender);
        QString content = QString::fromStdString(msg.content);
        QString timestamp = QString::fromStdString(msg.timestamp);
        
        // Save to database
        dbManager->saveMessage(sender, username, content, timestamp, false);
        dbManager->updateLastMessageTime(sender, timestamp);
        
        // If this is from the current chat partner, update the chat view
        if (sender == currentChatPartner) {
            addChatMessage(sender, content, timestamp, false);
        }
        
        // Increment message counter for perfect forward secrecy
        if (sender == currentChatPartner) {
            messageCounter++;
            
            // Check if key needs refresh (more than 100 messages)
            if (messageCounter >= 100) {
                initiateKeyExchange(currentChatPartner);
                messageCounter = 0;
            }
        }
    }
    
    void handleProofOfWorkChallenge(const Message& msg) {
        // Run proof of work solver in a separate thread to avoid blocking UI
        QFuture<void> future = QtConcurrent::run([this, msg]() {
            std::string challenge = msg.content;
            std::string solution = ProofOfWork::solveChallenge(challenge, 16);
            
            // Send the solution
            Message response;
            response.type = Message::PROOF_OF_WORK_RESPONSE;
            response.sender = username.toStdString();
            response.content = solution;
            response.timestamp = Message::getCurrentTimestamp();
            
            socket->sendMessage(response);
            
            // After sending solution, identify ourselves to the server
            Message connectMsg;
            connectMsg.type = Message::CONNECT;
            connectMsg.sender = username.toStdString();
            connectMsg.timestamp = Message::getCurrentTimestamp();
            
            socket->sendMessage(connectMsg);
            
            // Update UI
            QMetaObject::invokeMethod(this, "updateConnectionStatus", Qt::QueuedConnection);
        });
    }
    
    void updateConnectionStatus() {
        connectionStatus->setText("Connected as " + username);
        
        // Request client list
        requestClientList();
        
        // Load friends list
        loadFriendsList();
    }
    
    // This is handled by our earlier implementation
    void handleSocketError(const std::string& errorMsg) {
        handleSocketError(QString::fromStdString(errorMsg));
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    ChatClient client;
    client.show();
    
    return app.exec();
}





#include "client.moc"
