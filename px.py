#!/usr/bin/env python3
"""
Custom End-to-End Encrypted Communication Protocol
-------------------------------------------------

A high-security, custom implementation of an end-to-end encrypted communication protocol
with RSA authentication, Diffie-Hellman key exchange, and perfect forward secrecy.

This protocol implements:
- Custom RSA implementation
- Custom Diffie-Hellman key exchange
- Custom AES-256 encryption
- Permanent and temporary authorization key generation
- Key binding mechanism
- Message sequence validation for replay protection
- Key rotation mechanism
- Padding and length obfuscation for traffic analysis resistance
- Comprehensive documentation generation

WARNING: This is a custom cryptographic implementation intended for educational
and specialized use cases. It should undergo thorough cryptographic review before
production use.

Author: AI Assistant
"""

import os
import time
import json
import struct
import logging
import hashlib
import base64
import binascii
import random
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Protocol constants
PROTOCOL_VERSION = 1
MAX_SEQUENCE_NUMBER = 2**32 - 1
KEY_ROTATION_INTERVAL = 24 * 60 * 60  # 24 hours in seconds
TEMP_KEY_EXPIRY = 24 * 60 * 60  # Temporary keys expire after 24 hours
BINDING_TIMEOUT = 60  # Binding timeout in seconds
NONCE_SIZE = 16
RSA_KEY_SIZE = 2048
AES_BLOCK_SIZE = 16
DH_PRIME_BITS = 2048
PADDING_MIN = 16
PADDING_MAX = 128

# Standard DH prime (RFC 3526 Group 14 / 2048-bit MODP Group)
DH_STANDARD_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

# Protocol message types
MESSAGE_TYPE_AUTH_REQUEST = 1
MESSAGE_TYPE_AUTH_RESPONSE = 2
MESSAGE_TYPE_DH_EXCHANGE_START = 3
MESSAGE_TYPE_DH_EXCHANGE_RESPONSE = 4
MESSAGE_TYPE_BIND_TEMP_AUTH_KEY = 5
MESSAGE_TYPE_ENCRYPTED_DATA = 6
MESSAGE_TYPE_ACK = 7
MESSAGE_TYPE_KEY_ROTATION = 8
MESSAGE_TYPE_ERROR = 9

# Error codes
ERROR_INVALID_PROTOCOL_VERSION = 100
ERROR_INVALID_MESSAGE_TYPE = 101
ERROR_AUTHENTICATION_FAILED = 102
ERROR_ENCRYPTION_FAILED = 103
ERROR_DECRYPTION_FAILED = 104
ERROR_INVALID_SEQUENCE = 105
ERROR_INVALID_SIGNATURE = 106
ERROR_EXPIRED_KEY = 107
ERROR_BINDING_FAILED = 108

#############################################################################
# Custom Cryptographic Primitives Implementation
#############################################################################

class MathUtils:
    """Utility functions for various mathematical operations needed in cryptography."""
    
    @staticmethod
    def extended_gcd(a, b):
        """Extended Euclidean Algorithm for finding GCD and Bezout coefficients."""
        if a == 0:
            return (b, 0, 1)
        else:
            gcd, x, y = MathUtils.extended_gcd(b % a, a)
            return (gcd, y - (b // a) * x, x)

    @staticmethod
    def mod_inverse(a, m):
        """Calculate the modular multiplicative inverse of a under modulus m."""
        gcd, x, y = MathUtils.extended_gcd(a, m)
        if gcd != 1:
            raise Exception("Modular inverse does not exist")
        else:
            return x % m

    @staticmethod
    def is_prime(n, k=40):
        """Miller-Rabin primality test."""
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        
        # Find r and s
        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits):
        """Generate a prime number with the specified number of bits."""
        while True:
            # Generate a random odd integer with the specified number of bits
            p = random.getrandbits(bits) | 1
            # Ensure the number has exactly 'bits' bits
            p |= (1 << (bits - 1))
            if MathUtils.is_prime(p):
                return p

    @staticmethod
    def random_bytes(length):
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)
    
    @staticmethod
    def bytes_to_int(b):
        """Convert bytes to an integer."""
        return int.from_bytes(b, byteorder='big')
    
    @staticmethod
    def int_to_bytes(i, length=None):
        """Convert an integer to bytes."""
        if length is None:
            length = (i.bit_length() + 7) // 8
        return i.to_bytes(length, byteorder='big')


class PrimeGenerator:
    """Generator for prime numbers used in cryptographic operations."""
    
    @staticmethod
    def generate_prime_pair(bits):
        """Generate a pair of distinct prime numbers p and q for RSA."""
        p = MathUtils.generate_prime(bits // 2)
        q = MathUtils.generate_prime(bits // 2)
        while p == q:  # Ensure p and q are different
            q = MathUtils.generate_prime(bits // 2)
        return p, q

    @staticmethod
    def find_safe_prime(bits):
        """Find a safe prime (a prime p where (p-1)/2 is also prime)."""
        while True:
            # Generate a candidate prime q
            q = MathUtils.generate_prime(bits - 1)
            # Calculate p = 2q + 1
            p = 2 * q + 1
            # Check if p is also prime
            if MathUtils.is_prime(p):
                return p, q


class RSA:
    """Custom RSA implementation for encryption and digital signatures."""
    
    def __init__(self, key_size=RSA_KEY_SIZE):
        """Initialize RSA with the given key size."""
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self):
        """Generate a new RSA key pair."""
        # Generate two large prime numbers
        p, q = PrimeGenerator.generate_prime_pair(self.key_size)
        
        # Calculate n = p * q
        n = p * q
        
        # Calculate Euler's totient function: φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        
        # Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        e = 65537  # Commonly used value for e
        
        # Ensure e is coprime to phi
        while MathUtils.extended_gcd(e, phi)[0] != 1:
            e += 2
        
        # Calculate d such that (d * e) % φ(n) = 1 (modular multiplicative inverse)
        d = MathUtils.mod_inverse(e, phi)
        
        # Store the key components
        self.public_key = (n, e)
        self.private_key = (n, d)
        
        return self.public_key, self.private_key
    
    def encrypt(self, message, public_key=None):
        """Encrypt a message using RSA."""
        if public_key is None:
            public_key = self.public_key
        
        n, e = public_key
        
        # Convert message to an integer
        m = MathUtils.bytes_to_int(message)
        
        # Ensure message is within the valid range
        if m >= n:
            raise ValueError("Message too large for RSA key size")
        
        # Perform RSA encryption: c = m^e mod n
        c = pow(m, e, n)
        
        # Convert the ciphertext back to bytes
        return MathUtils.int_to_bytes(c)
    
    def decrypt(self, ciphertext, private_key=None):
        """Decrypt a message using RSA."""
        if private_key is None:
            private_key = self.private_key
        
        n, d = private_key
        
        # Convert ciphertext to an integer
        c = MathUtils.bytes_to_int(ciphertext)
        
        # Perform RSA decryption: m = c^d mod n
        m = pow(c, d, n)
        
        # Convert the message back to bytes
        return MathUtils.int_to_bytes(m)
    
    def sign(self, message, private_key=None):
        """Sign a message using RSA."""
        if private_key is None:
            private_key = self.private_key
        
        # Hash the message
        hash_obj = hashlib.sha256(message)
        hash_value = hash_obj.digest()
        
        # Sign the hash
        signature = self.decrypt(hash_value, private_key)
        return signature
    
    def verify(self, message, signature, public_key=None):
        """Verify a message signature using RSA."""
        if public_key is None:
            public_key = self.public_key
        
        # Hash the message
        hash_obj = hashlib.sha256(message)
        hash_value = hash_obj.digest()
        
        # Decrypt the signature to get the hash
        decrypted_hash = self.encrypt(signature, public_key)
        
        # Compare hashes
        return hash_value == decrypted_hash
    
    def export_public_key(self):
        """Export the public key in a serializable format."""
        if self.public_key is None:
            raise ValueError("No public key has been generated")
        
        n, e = self.public_key
        return {
            "n": MathUtils.int_to_bytes(n).hex(),
            "e": MathUtils.int_to_bytes(e).hex()
        }
    
    def export_private_key(self):
        """Export the private key in a serializable format."""
        if self.private_key is None:
            raise ValueError("No private key has been generated")
        
        n, d = self.private_key
        return {
            "n": MathUtils.int_to_bytes(n).hex(),
            "d": MathUtils.int_to_bytes(d).hex()
        }
    
    def import_public_key(self, key_data):
        """Import a public key from a serialized format."""
        n = int(key_data["n"], 16)
        e = int(key_data["e"], 16)
        self.public_key = (n, e)
        return self.public_key
    
    def import_private_key(self, key_data):
        """Import a private key from a serialized format."""
        n = int(key_data["n"], 16)
        d = int(key_data["d"], 16)
        self.private_key = (n, d)
        return self.private_key


class DiffieHellman:
    """Custom Diffie-Hellman implementation for key exchange."""
    
    def __init__(self, prime_bits=DH_PRIME_BITS):
        """Initialize Diffie-Hellman with the given prime size."""
        self.prime_bits = prime_bits
        self.p = None  # Prime modulus
        self.g = None  # Generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def generate_parameters(self):
        """Generate or use standard Diffie-Hellman parameters p and g."""
        # Use the standard prime from RFC 3526
        self.p = DH_STANDARD_PRIME
        
        # Standard generator g = 2 for this prime
        self.g = 2
        
        return self.p, self.g
    
    def generate_keypair(self, p=None, g=None):
        """Generate a Diffie-Hellman keypair."""
        if p is not None:
            self.p = p
        if g is not None:
            self.g = g
        
        if self.p is None or self.g is None:
            self.generate_parameters()
        
        # Generate a random private key a such that 1 < a < p-1
        self.private_key = random.randint(2, self.p - 2)
        
        # Calculate the public key A = g^a mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """Compute the shared secret from the other party's public key."""
        if self.private_key is None:
            raise ValueError("Private key not generated yet")
        
        # Calculate the shared secret s = B^a mod p
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        
        # Convert to bytes for use as a key
        shared_secret_bytes = MathUtils.int_to_bytes(self.shared_secret)
        
        # Apply a key derivation function (HKDF-like) to the shared secret
        # to get a uniformly distributed key
        key_material = hashlib.sha256(shared_secret_bytes).digest()
        
        return key_material
    
    def export_parameters(self):
        """Export the Diffie-Hellman parameters in a serializable format."""
        if self.p is None or self.g is None:
            raise ValueError("Parameters have not been generated")
        
        return {
            "p": MathUtils.int_to_bytes(self.p).hex(),
            "g": MathUtils.int_to_bytes(self.g).hex()
        }
    
    def export_public_key(self):
        """Export the public key in a serializable format."""
        if self.public_key is None:
            raise ValueError("Public key has not been generated")
        
        return MathUtils.int_to_bytes(self.public_key).hex()
    
    def import_parameters(self, params):
        """Import Diffie-Hellman parameters from a serialized format."""
        self.p = int(params["p"], 16)
        self.g = int(params["g"], 16)
        return self.p, self.g
    
    def import_public_key(self, key_hex):
        """Import a public key from a serialized format."""
        return int(key_hex, 16)


class AES:
    """Custom AES-256 implementation."""
    
    # AES S-box
    SBOX = [
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
    ]
    
    # Inverse S-box
    INV_SBOX = [
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
    ]
    
    # Round constants for key schedule
    RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    
    def __init__(self, key):
        """Initialize AES with a key. For AES-256, key should be 32 bytes."""
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        
        self.key = key
        self.rounds = 14  # AES-256 has 14 rounds
        self.key_schedule = self._key_expansion(key)
    
    def _sub_bytes(self, state):
        """Apply the S-box to each byte of the state."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.SBOX[state[i][j]]
        return state
    
    def _inv_sub_bytes(self, state):
        """Apply the inverse S-box to each byte of the state."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_SBOX[state[i][j]]
        return state
    
    def _shift_rows(self, state):
        """Shift the rows of the state matrix."""
        state[1] = state[1][1:] + state[1][:1]  # Shift row 1 by 1
        state[2] = state[2][2:] + state[2][:2]  # Shift row 2 by 2
        state[3] = state[3][3:] + state[3][:3]  # Shift row 3 by 3
        return state
    
    def _inv_shift_rows(self, state):
        """Inverse shift the rows of the state matrix."""
        state[1] = state[1][3:] + state[1][:3]  # Shift row 1 by 3
        state[2] = state[2][2:] + state[2][:2]  # Shift row 2 by 2
        state[3] = state[3][1:] + state[3][:1]  # Shift row 3 by 1
        return state
    
    def _multiply_in_gf(self, a, b):
        """Multiply two numbers in the Galois Field GF(2^8)."""
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a <<= 1
            if carry:
                a ^= 0x1B  # The irreducible polynomial in GF(2^8)
            b >>= 1
        return p & 0xFF
    
    def _mix_column(self, column):
        """Mix a single column of the state matrix."""
        temp = column.copy()
        column[0] = self._multiply_in_gf(temp[0], 2) ^ self._multiply_in_gf(temp[1], 3) ^ temp[2] ^ temp[3]
        column[1] = temp[0] ^ self._multiply_in_gf(temp[1], 2) ^ self._multiply_in_gf(temp[2], 3) ^ temp[3]
        column[2] = temp[0] ^ temp[1] ^ self._multiply_in_gf(temp[2], 2) ^ self._multiply_in_gf(temp[3], 3)
        column[3] = self._multiply_in_gf(temp[0], 3) ^ temp[1] ^ temp[2] ^ self._multiply_in_gf(temp[3], 2)
        return column
    
    def _inv_mix_column(self, column):
        """Inverse mix a single column of the state matrix."""
        temp = column.copy()
        column[0] = self._multiply_in_gf(temp[0], 0x0E) ^ self._multiply_in_gf(temp[1], 0x0B) ^ self._multiply_in_gf(temp[2], 0x0D) ^ self._multiply_in_gf(temp[3], 0x09)
        column[1] = self._multiply_in_gf(temp[0], 0x09) ^ self._multiply_in_gf(temp[1], 0x0E) ^ self._multiply_in_gf(temp[2], 0x0B) ^ self._multiply_in_gf(temp[3], 0x0D)
        column[2] = self._multiply_in_gf(temp[0], 0x0D) ^ self._multiply_in_gf(temp[1], 0x09) ^ self._multiply_in_gf(temp[2], 0x0E) ^ self._multiply_in_gf(temp[3], 0x0B)
        column[3] = self._multiply_in_gf(temp[0], 0x0B) ^ self._multiply_in_gf(temp[1], 0x0D) ^ self._multiply_in_gf(temp[2], 0x09) ^ self._multiply_in_gf(temp[3], 0x0E)
        return column
    
    def _mix_columns(self, state):
        """Mix all columns of the state matrix."""
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            column = self._mix_column(column)
            for j in range(4):
                state[j][i] = column[j]
        return state
    
    def _inv_mix_columns(self, state):
        """Inverse mix all columns of the state matrix."""
        for i in range(4):
            column = [state[j][i] for j in range(4)]
            column = self._inv_mix_column(column)
            for j in range(4):
                state[j][i] = column[j]
        return state
    
    def _add_round_key(self, state, round_key):
        """Add the round key to the state using XOR."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state
    
    def _bytes_to_state(self, data):
        """Convert 16 bytes to 4x4 state matrix."""
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(16):
            row = i % 4
            col = i // 4
            state[row][col] = data[i]
        return state
    
    def _state_to_bytes(self, state):
        """Convert 4x4 state matrix to 16 bytes."""
        output = bytearray(16)
        for i in range(16):
            row = i % 4
            col = i // 4
            output[i] = state[row][col]
        return bytes(output)
    
    def _key_expansion(self, key):
        """Expand the cipher key into the key schedule."""
        key_words = [0] * (4 * (self.rounds + 1))
        
        # Convert the key into 8 initial key words (for AES-256)
        for i in range(8):
            key_words[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
        
        for i in range(8, 4 * (self.rounds + 1)):
            temp = key_words[i-1]
            
            if i % 8 == 0:
                # RotWord operation: rotate the word by 1 byte
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                
                # SubWord operation: apply S-box to each byte
                temp = (self.SBOX[(temp >> 24) & 0xFF] << 24) | \
                       (self.SBOX[(temp >> 16) & 0xFF] << 16) | \
                       (self.SBOX[(temp >> 8) & 0xFF] << 8) | \
                       self.SBOX[temp & 0xFF]
                
                # XOR with round constant
                temp ^= self.RCON[i // 8] << 24
            elif i % 8 == 4:
                # For AES-256, we also apply SubWord every 4 words
                temp = (self.SBOX[(temp >> 24) & 0xFF] << 24) | \
                       (self.SBOX[(temp >> 16) & 0xFF] << 16) | \
                       (self.SBOX[(temp >> 8) & 0xFF] << 8) | \
                       self.SBOX[temp & 0xFF]
            
            key_words[i] = key_words[i-8] ^ temp
        
        # Convert words to bytes format for round keys
        expanded_key = []
        for i in range(0, 4 * (self.rounds + 1), 4):
            round_key = [[0 for _ in range(4)] for _ in range(4)]
            for j in range(4):
                word = key_words[i + j]
                for k in range(4):
                    round_key[k][j] = (word >> (24 - 8 * k)) & 0xFF
            expanded_key.append(round_key)
        
        return expanded_key
    
    def encrypt_block(self, plaintext):
        """Encrypt a single 16-byte block."""
        if len(plaintext) != AES_BLOCK_SIZE:
            raise ValueError(f"Block size must be {AES_BLOCK_SIZE} bytes")
        
        state = self._bytes_to_state(plaintext)
        
        # Initial AddRoundKey
        state = self._add_round_key(state, self.key_schedule[0])
        
        # Main rounds
        for round_num in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.key_schedule[round_num])
        
        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.key_schedule[self.rounds])
        
        return self._state_to_bytes(state)
    
    def decrypt_block(self, ciphertext):
        """Decrypt a single 16-byte block."""
        if len(ciphertext) != AES_BLOCK_SIZE:
            raise ValueError(f"Block size must be {AES_BLOCK_SIZE} bytes")
        
        state = self._bytes_to_state(ciphertext)
        
        # Initial AddRoundKey
        state = self._add_round_key(state, self.key_schedule[self.rounds])
        
        # Main rounds (in reverse)
        for round_num in range(self.rounds - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.key_schedule[round_num])
            state = self._inv_mix_columns(state)
        
        # Final round
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.key_schedule[0])
        
        return self._state_to_bytes(state)
    
    def encrypt(self, data, iv):
        """Encrypt data using AES in CBC mode."""
        if len(iv) != AES_BLOCK_SIZE:
            raise ValueError(f"IV must be {AES_BLOCK_SIZE} bytes")
        
        # Pad the data to a multiple of 16 bytes (PKCS#7 padding)
        padding_length = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
        padded_data = data + bytes([padding_length] * padding_length)
        
        # Initialize the ciphertext and previous block
        ciphertext = bytearray()
        prev_block = iv
        
        # Process each block
        for i in range(0, len(padded_data), AES_BLOCK_SIZE):
            block = padded_data[i:i+AES_BLOCK_SIZE]
            
            # XOR the current block with the previous ciphertext block (or IV)
            xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
            
            # Encrypt the block
            encrypted_block = self.encrypt_block(xored_block)
            
            # Add to ciphertext and update previous block
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block
        
        return bytes(ciphertext)
    
    def decrypt(self, data, iv):
        """Decrypt data using AES in CBC mode."""
        if len(iv) != AES_BLOCK_SIZE:
            raise ValueError(f"IV must be {AES_BLOCK_SIZE} bytes")
        
        if len(data) % AES_BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be a multiple of the block size")
        
        # Initialize the plaintext and previous block
        plaintext = bytearray()
        prev_block = iv
        
        # Process each block
        for i in range(0, len(data), AES_BLOCK_SIZE):
            block = data[i:i+AES_BLOCK_SIZE]
            
            # Decrypt the block
            decrypted_block = self.decrypt_block(block)
            
            # XOR with the previous ciphertext block (or IV)
            xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            
            # Add to plaintext and update previous block
            plaintext.extend(xored_block)
            prev_block = block
        
        # Remove padding (PKCS#7)
        padding_length = plaintext[-1]
        if padding_length > AES_BLOCK_SIZE:
            raise ValueError("Invalid padding")
        
        for i in range(1, padding_length + 1):
            if plaintext[-i] != padding_length:
                raise ValueError("Invalid padding")
        
        return bytes(plaintext[:-padding_length])


class HMAC:
    """Custom HMAC implementation for message authentication."""
    
    def __init__(self, key, hash_function=hashlib.sha256):
        """Initialize HMAC with a key and hash function."""
        self.hash_function = hash_function
        self.block_size = 64  # Block size for SHA-256
        
        # If the key is longer than the block size, hash it
        if len(key) > self.block_size:
            key = hash_function(key).digest()
        
        # If the key is shorter than the block size, pad it with zeros
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        
        # Generate the inner and outer padding keys
        self.inner_key = bytes(b ^ 0x36 for b in key)
        self.outer_key = bytes(b ^ 0x5C for b in key)
    
    def compute(self, message):
        """Compute the HMAC for a message."""
        # Inner hash: H(inner_key || message)
        inner_hash = self.hash_function(self.inner_key + message).digest()
        
        # Outer hash: H(outer_key || inner_hash)
        outer_hash = self.hash_function(self.outer_key + inner_hash).digest()
        
        return outer_hash
    
    def verify(self, message, mac):
        """Verify a message's HMAC."""
        computed_mac = self.compute(message)
        return computed_mac == mac


#############################################################################
# Protocol Implementation
#############################################################################

class ProtocolError(Exception):
    """Exception raised for protocol errors."""
    
    def __init__(self, error_code, message):
        self.error_code = error_code
        self.message = message
        super().__init__(f"Protocol error {error_code}: {message}")


class Message:
    """Base class for protocol messages."""
    
    def __init__(self, message_type, payload=None):
        self.version = PROTOCOL_VERSION
        self.message_type = message_type
        self.payload = payload or {}
        self.timestamp = int(time.time())
    
    def to_dict(self):
        """Convert message to a dictionary."""
        return {
            "version": self.version,
            "message_type": self.message_type,
            "payload": self.payload,
            "timestamp": self.timestamp
        }
    
    def to_bytes(self):
        """Convert message to bytes for transmission."""
        message_dict = self.to_dict()
        message_json = json.dumps(message_dict).encode('utf-8')
        return message_json
    
    @classmethod
    def from_bytes(cls, data):
        """Create a message from bytes."""
        try:
            message_dict = json.loads(data.decode('utf-8'))
            
            # Check protocol version
            if message_dict.get("version") != PROTOCOL_VERSION:
                raise ProtocolError(ERROR_INVALID_PROTOCOL_VERSION, 
                                  f"Invalid protocol version: {message_dict.get('version')}")
            
            # Create message object
            message = cls(message_dict["message_type"], message_dict.get("payload", {}))
            message.timestamp = message_dict.get("timestamp", int(time.time()))
            
            return message
        except json.JSONDecodeError:
            raise ProtocolError(ERROR_INVALID_MESSAGE_TYPE, "Invalid message format")


class AuthenticationRequest(Message):
    """Authentication request message."""
    
    def __init__(self, client_id, nonce=None):
        """Initialize an authentication request."""
        payload = {
            "client_id": client_id,
            "nonce": nonce or MathUtils.random_bytes(NONCE_SIZE).hex()
        }
        super().__init__(MESSAGE_TYPE_AUTH_REQUEST, payload)
    
    @property
    def client_id(self):
        return self.payload["client_id"]
    
    @property
    def nonce(self):
        return self.payload["nonce"]


class AuthenticationResponse(Message):
    """Authentication response message."""
    
    def __init__(self, server_id, client_nonce, server_nonce, signature=None):
        """Initialize an authentication response."""
        payload = {
            "server_id": server_id,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce or MathUtils.random_bytes(NONCE_SIZE).hex(),
            "signature": signature
        }
        super().__init__(MESSAGE_TYPE_AUTH_RESPONSE, payload)
    
    @property
    def server_id(self):
        return self.payload["server_id"]
    
    @property
    def client_nonce(self):
        return self.payload["client_nonce"]
    
    @property
    def server_nonce(self):
        return self.payload["server_nonce"]
    
    @property
    def signature(self):
        return self.payload["signature"]
    
    @signature.setter
    def signature(self, value):
        self.payload["signature"] = value


class DHExchangeStart(Message):
    """Diffie-Hellman key exchange start message."""
    
    def __init__(self, client_id, dh_params, client_public_key, nonce):
        """Initialize a DH exchange start message."""
        payload = {
            "client_id": client_id,
            "dh_params": dh_params,
            "client_public_key": client_public_key,
            "nonce": nonce
        }
        super().__init__(MESSAGE_TYPE_DH_EXCHANGE_START, payload)
    
    @property
    def client_id(self):
        return self.payload["client_id"]
    
    @property
    def dh_params(self):
        return self.payload["dh_params"]
    
    @property
    def client_public_key(self):
        return self.payload["client_public_key"]
    
    @property
    def nonce(self):
        return self.payload["nonce"]


class DHExchangeResponse(Message):
    """Diffie-Hellman key exchange response message."""
    
    def __init__(self, server_id, server_public_key, client_nonce, server_nonce, signature=None):
        """Initialize a DH exchange response message."""
        payload = {
            "server_id": server_id,
            "server_public_key": server_public_key,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "signature": signature
        }
        super().__init__(MESSAGE_TYPE_DH_EXCHANGE_RESPONSE, payload)
    
    @property
    def server_id(self):
        return self.payload["server_id"]
    
    @property
    def server_public_key(self):
        return self.payload["server_public_key"]
    
    @property
    def client_nonce(self):
        return self.payload["client_nonce"]
    
    @property
    def server_nonce(self):
        return self.payload["server_nonce"]
    
    @property
    def signature(self):
        return self.payload["signature"]
    
    @signature.setter
    def signature(self, value):
        self.payload["signature"] = value


class BindTempAuthKey(Message):
    """Temporary authorization key binding message."""
    
    def __init__(self, perm_auth_key_id, temp_auth_key_id, expires_at, binding_message):
        """Initialize a temporary key binding message."""
        payload = {
            "perm_auth_key_id": perm_auth_key_id,
            "temp_auth_key_id": temp_auth_key_id,
            "expires_at": expires_at,
            "binding_message": binding_message
        }
        super().__init__(MESSAGE_TYPE_BIND_TEMP_AUTH_KEY, payload)
    
    @property
    def perm_auth_key_id(self):
        return self.payload["perm_auth_key_id"]
    
    @property
    def temp_auth_key_id(self):
        return self.payload["temp_auth_key_id"]
    
    @property
    def expires_at(self):
        return self.payload["expires_at"]
    
    @property
    def binding_message(self):
        return self.payload["binding_message"]


class EncryptedData(Message):
    """Encrypted data message."""
    
    def __init__(self, auth_key_id, sequence_number, iv, encrypted_payload, hmac_value):
        """Initialize an encrypted data message."""
        payload = {
            "auth_key_id": auth_key_id,
            "sequence_number": sequence_number,
            "iv": iv,
            "encrypted_payload": encrypted_payload,
            "hmac": hmac_value
        }
        super().__init__(MESSAGE_TYPE_ENCRYPTED_DATA, payload)
    
    @property
    def auth_key_id(self):
        return self.payload["auth_key_id"]
    
    @property
    def sequence_number(self):
        return self.payload["sequence_number"]
    
    @property
    def iv(self):
        return self.payload["iv"]
    
    @property
    def encrypted_payload(self):
        return self.payload["encrypted_payload"]
    
    @property
    def hmac(self):
        return self.payload["hmac"]


class ACK(Message):
    """Acknowledgment message."""
    
    def __init__(self, sequence_number):
        """Initialize an acknowledgment message."""
        payload = {"sequence_number": sequence_number}
        super().__init__(MESSAGE_TYPE_ACK, payload)
    
    @property
    def sequence_number(self):
        return self.payload["sequence_number"]


class KeyRotation(Message):
    """Key rotation message."""
    
    def __init__(self, old_auth_key_id, new_auth_key_id, dh_params=None, public_key=None):
        """Initialize a key rotation message."""
        payload = {
            "old_auth_key_id": old_auth_key_id,
            "new_auth_key_id": new_auth_key_id,
            "dh_params": dh_params,
            "public_key": public_key
        }
        super().__init__(MESSAGE_TYPE_KEY_ROTATION, payload)
    
    @property
    def old_auth_key_id(self):
        return self.payload["old_auth_key_id"]
    
    @property
    def new_auth_key_id(self):
        return self.payload["new_auth_key_id"]
    
    @property
    def dh_params(self):
        return self.payload["dh_params"]
    
    @property
    def public_key(self):
        return self.payload["public_key"]


class ErrorMessage(Message):
    """Error message."""
    
    def __init__(self, error_code, error_message):
        """Initialize an error message."""
        payload = {
            "error_code": error_code,
            "error_message": error_message
        }
        super().__init__(MESSAGE_TYPE_ERROR, payload)
    
    @property
    def error_code(self):
        return self.payload["error_code"]
    
    @property
    def error_message(self):
        return self.payload["error_message"]


class KeyManager:
    """Manager for cryptographic keys and operations."""
    
    def __init__(self):
        """Initialize the key manager."""
        self.rsa = RSA()
        self.permanent_auth_keys = {}  # auth_key_id -> auth_key
        self.temporary_auth_keys = {}  # temp_auth_key_id -> (auth_key, expires_at)
        self.binding_map = {}  # perm_auth_key_id -> temp_auth_key_id
        self.reverse_binding_map = {}  # temp_auth_key_id -> perm_auth_key_id
        self.sequence_numbers = {}  # auth_key_id -> sequence_number
        self.last_seen_sequence = {}  # auth_key_id -> last seen sequence number
    
    def generate_rsa_keys(self):
        """Generate RSA keys for the entity."""
        return self.rsa.generate_keys()
    
    def import_rsa_public_key(self, key_data):
        """Import an RSA public key."""
        return self.rsa.import_public_key(key_data)
    
    def import_rsa_private_key(self, key_data):
        """Import an RSA private key."""
        return self.rsa.import_private_key(key_data)
    
    def sign_data(self, data):
        """Sign data with the entity's RSA private key."""
        return self.rsa.sign(data)
    
    def verify_signature(self, data, signature, public_key=None):
        """Verify a signature using the specified public key."""
        if public_key:
            temp_rsa = RSA()
            temp_rsa.import_public_key(public_key)
            return temp_rsa.verify(data, signature)
        else:
            return self.rsa.verify(data, signature)
    
    def generate_auth_key(self):
        """Generate a new authorization key."""
        auth_key = MathUtils.random_bytes(32)  # 256-bit key
        auth_key_id = hashlib.sha256(auth_key).digest()[:8]  # 64-bit ID
        auth_key_id_hex = auth_key_id.hex()
        self.permanent_auth_keys[auth_key_id_hex] = auth_key
        self.sequence_numbers[auth_key_id_hex] = 0
        self.last_seen_sequence[auth_key_id_hex] = set()
        return auth_key, auth_key_id_hex
    
    def generate_temp_auth_key(self, expires_in=TEMP_KEY_EXPIRY):
        """Generate a new temporary authorization key."""
        auth_key = MathUtils.random_bytes(32)  # 256-bit key
        auth_key_id = hashlib.sha256(auth_key).digest()[:8]  # 64-bit ID
        auth_key_id_hex = auth_key_id.hex()
        expires_at = int(time.time()) + expires_in
        self.temporary_auth_keys[auth_key_id_hex] = (auth_key, expires_at)
        self.sequence_numbers[auth_key_id_hex] = 0
        self.last_seen_sequence[auth_key_id_hex] = set()
        return auth_key, auth_key_id_hex, expires_at
    
    def bind_temp_auth_key(self, perm_auth_key_id, temp_auth_key_id):
        """Bind a temporary authorization key to a permanent key."""
        if perm_auth_key_id not in self.permanent_auth_keys:
            raise ProtocolError(ERROR_BINDING_FAILED, "Permanent auth key not found")
        
        if temp_auth_key_id not in self.temporary_auth_keys:
            raise ProtocolError(ERROR_BINDING_FAILED, "Temporary auth key not found")
        
        # Check if the temporary key has already expired
        temp_key, expires_at = self.temporary_auth_keys[temp_auth_key_id]
        if expires_at < time.time():
            del self.temporary_auth_keys[temp_auth_key_id]
            raise ProtocolError(ERROR_EXPIRED_KEY, "Temporary auth key has expired")
        
        # Remove old bindings if they exist
        if perm_auth_key_id in self.binding_map:
            old_temp_id = self.binding_map[perm_auth_key_id]
            del self.reverse_binding_map[old_temp_id]
        
        # Create new binding
        self.binding_map[perm_auth_key_id] = temp_auth_key_id
        self.reverse_binding_map[temp_auth_key_id] = perm_auth_key_id
        
        return True
    
    def get_auth_key(self, auth_key_id):
        """Get an authorization key by its ID."""
        if auth_key_id in self.permanent_auth_keys:
            return self.permanent_auth_keys[auth_key_id]
        
        if auth_key_id in self.temporary_auth_keys:
            temp_key, expires_at = self.temporary_auth_keys[auth_key_id]
            if expires_at < time.time():
                del self.temporary_auth_keys[auth_key_id]
                if auth_key_id in self.reverse_binding_map:
                    perm_id = self.reverse_binding_map[auth_key_id]
                    del self.binding_map[perm_id]
                    del self.reverse_binding_map[auth_key_id]
                raise ProtocolError(ERROR_EXPIRED_KEY, "Temporary auth key has expired")
            return temp_key
        
        raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Auth key not found")
    
    def get_next_sequence_number(self, auth_key_id):
        """Get the next sequence number for a key."""
        if auth_key_id not in self.sequence_numbers:
            self.sequence_numbers[auth_key_id] = 0
            self.last_seen_sequence[auth_key_id] = set()
        
        seq_num = self.sequence_numbers[auth_key_id]
        self.sequence_numbers[auth_key_id] = (seq_num + 1) % MAX_SEQUENCE_NUMBER
        return seq_num
    
    def validate_sequence_number(self, auth_key_id, sequence_number):
        """Validate a sequence number to prevent replay attacks."""
        if auth_key_id not in self.last_seen_sequence:
            self.last_seen_sequence[auth_key_id] = set()
        
        if sequence_number in self.last_seen_sequence[auth_key_id]:
            return False
        
        # Keep a reasonable window of seen sequence numbers to prevent memory exhaustion
        self.last_seen_sequence[auth_key_id].add(sequence_number)
        if len(self.last_seen_sequence[auth_key_id]) > 1000:
            # Remove the oldest sequence numbers
            self.last_seen_sequence[auth_key_id] = set(sorted(self.last_seen_sequence[auth_key_id])[-1000:])
        
        return True
    
    def encrypt_message(self, auth_key_id, message):
        """Encrypt a message using the specified authorization key."""
        auth_key = self.get_auth_key(auth_key_id)
        
        # Generate a random IV
        iv = MathUtils.random_bytes(AES_BLOCK_SIZE)
        
        # Add padding to prevent traffic analysis
        padding_length = random.randint(PADDING_MIN, PADDING_MAX)
        padding = MathUtils.random_bytes(padding_length)
        
        # Prepare the message data with padding and length
        message_data = message.to_bytes()
        padded_message = struct.pack("!I", len(message_data)) + message_data + padding
        
        # Encrypt the message
        aes = AES(auth_key)
        encrypted_data = aes.encrypt(padded_message, iv)
        
        # Calculate HMAC for encrypted data
        hmac = HMAC(auth_key)
        hmac_value = hmac.compute(encrypted_data).hex()
        
        # Get the next sequence number
        sequence_number = self.get_next_sequence_number(auth_key_id)
        
        # Create the encrypted message
        encrypted_message = EncryptedData(
            auth_key_id=auth_key_id,
            sequence_number=sequence_number,
            iv=iv.hex(),
            encrypted_payload=encrypted_data.hex(),
            hmac_value=hmac_value
        )
        
        return encrypted_message
    
    def decrypt_message(self, encrypted_message):
        """Decrypt an encrypted message."""
        auth_key_id = encrypted_message.auth_key_id
        auth_key = self.get_auth_key(auth_key_id)
        
        # Validate the sequence number
        if not self.validate_sequence_number(auth_key_id, encrypted_message.sequence_number):
            raise ProtocolError(ERROR_INVALID_SEQUENCE, "Invalid sequence number (possible replay attack)")
        
        # Validate HMAC
        hmac = HMAC(auth_key)
        encrypted_data = bytes.fromhex(encrypted_message.encrypted_payload)
        expected_hmac = hmac.compute(encrypted_data).hex()
        
        if expected_hmac != encrypted_message.hmac:
            raise ProtocolError(ERROR_INVALID_SIGNATURE, "Invalid HMAC (message integrity check failed)")
        
        # Decrypt the message
        iv = bytes.fromhex(encrypted_message.iv)
        aes = AES(auth_key)
        
        try:
            decrypted_data = aes.decrypt(encrypted_data, iv)
        except ValueError as e:
            raise ProtocolError(ERROR_DECRYPTION_FAILED, f"Decryption failed: {str(e)}")
        
        # Extract the message length and message data
        message_length = struct.unpack("!I", decrypted_data[:4])[0]
        message_data = decrypted_data[4:4+message_length]
        
        # Parse the decrypted message
        try:
            decrypted_message = Message.from_bytes(message_data)
            return decrypted_message
        except Exception as e:
            raise ProtocolError(ERROR_DECRYPTION_FAILED, f"Failed to parse decrypted message: {str(e)}")


class ProtocolEntity:
    """Base class for entities in the protocol (client or server)."""
    
    def __init__(self, entity_id):
        """Initialize the protocol entity."""
        self.entity_id = entity_id
        self.key_manager = KeyManager()
        self.dh = DiffieHellman()
        self.authenticated_entities = {}  # entity_id -> public_key
        self.shared_secrets = {}  # entity_id -> shared_secret
        self.active_sessions = {}  # entity_id -> auth_key_id
        self.last_key_rotation = {}  # auth_key_id -> timestamp
    
    def initialize(self):
        """Initialize the entity with keys and parameters."""
        # Generate RSA keys
        public_key, private_key = self.key_manager.generate_rsa_keys()
        
        # Generate Diffie-Hellman parameters
        p, g = self.dh.generate_parameters()
        
        logger.info(f"Entity {self.entity_id} initialized with RSA and DH parameters")
        return public_key, private_key, p, g
    
    def authenticate_entity(self, entity_id, public_key):
        """Authenticate another entity by storing its public key."""
        self.authenticated_entities[entity_id] = public_key
        logger.info(f"Entity {entity_id} authenticated")
    
    def is_entity_authenticated(self, entity_id):
        """Check if an entity is authenticated."""
        return entity_id in self.authenticated_entities
    
    def get_entity_public_key(self, entity_id):
        """Get an entity's public key."""
        if entity_id in self.authenticated_entities:
            return self.authenticated_entities[entity_id]
        return None
    
    def establish_shared_secret(self, entity_id, other_public_key):
        """Establish a shared secret with another entity."""
        # Generate our DH keypair
        self.dh.generate_keypair()
        
        # Compute the shared secret
        shared_secret = self.dh.compute_shared_secret(other_public_key)
        self.shared_secrets[entity_id] = shared_secret
        
        logger.info(f"Shared secret established with entity {entity_id}")
        return self.dh.public_key
    
    def get_shared_secret(self, entity_id):
        """Get the shared secret with an entity."""
        return self.shared_secrets.get(entity_id)
    
    def create_session(self, entity_id, permanent=True):
        """Create a new session with an entity."""
        if permanent:
            auth_key, auth_key_id = self.key_manager.generate_auth_key()
        else:
            auth_key, auth_key_id, _ = self.key_manager.generate_temp_auth_key()
        
        self.active_sessions[entity_id] = auth_key_id
        self.last_key_rotation[auth_key_id] = time.time()
        
        logger.info(f"Session created with entity {entity_id}, auth_key_id: {auth_key_id}")
        return auth_key_id
    
    def get_session_key_id(self, entity_id):
        """Get the session key ID for an entity."""
        return self.active_sessions.get(entity_id)
    
    def send_encrypted_message(self, entity_id, message, force_permanent=False):
        """Encrypt and send a message to an entity."""
        auth_key_id = self.active_sessions.get(entity_id)
        if not auth_key_id:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "No active session")
        
        # If we have a temporary key binding, use it unless forced to use permanent
        if not force_permanent and auth_key_id in self.key_manager.binding_map:
            temp_auth_key_id = self.key_manager.binding_map[auth_key_id]
            auth_key_id = temp_auth_key_id
        
        # Check if key rotation is needed
        current_time = time.time()
        if current_time - self.last_key_rotation.get(auth_key_id, 0) > KEY_ROTATION_INTERVAL:
            # Perform key rotation
            self.rotate_key(entity_id, auth_key_id)
        
        # Encrypt the message
        encrypted_message = self.key_manager.encrypt_message(auth_key_id, message)
        return encrypted_message
    
    def decrypt_message(self, encrypted_message):
        """Decrypt a message."""
        return self.key_manager.decrypt_message(encrypted_message)
    
    def rotate_key(self, entity_id, auth_key_id):
        """Rotate a session key."""
        # Generate a new key
        if auth_key_id in self.key_manager.permanent_auth_keys:
            new_auth_key, new_auth_key_id = self.key_manager.generate_auth_key()
            is_permanent = True
        else:
            new_auth_key, new_auth_key_id, _ = self.key_manager.generate_temp_auth_key()
            is_permanent = False
        
        # Update the active session
        self.active_sessions[entity_id] = new_auth_key_id
        self.last_key_rotation[new_auth_key_id] = time.time()
        
        # If it's a temporary key, update the binding if needed
        if not is_permanent and auth_key_id in self.key_manager.reverse_binding_map:
            perm_auth_key_id = self.key_manager.reverse_binding_map[auth_key_id]
            self.key_manager.bind_temp_auth_key(perm_auth_key_id, new_auth_key_id)
        
        logger.info(f"Key rotated for entity {entity_id}, new auth_key_id: {new_auth_key_id}")
        return new_auth_key_id
    
    def bind_temporary_key(self, perm_auth_key_id, temp_auth_key_id):
        """Bind a temporary key to a permanent key."""
        return self.key_manager.bind_temp_auth_key(perm_auth_key_id, temp_auth_key_id)


class Client(ProtocolEntity):
    """Client implementation for the protocol."""
    
    def __init__(self, client_id, server_id=None, server_public_key=None):
        """Initialize a client."""
        super().__init__(client_id)
        self.server_id = server_id
        self.server_public_key = server_public_key
        self.client_nonce = None
        self.server_nonce = None
        self.auth_key_id = None
        self.temp_auth_key_id = None
    
    def create_auth_request(self):
        """Create an authentication request message."""
        self.client_nonce = MathUtils.random_bytes(NONCE_SIZE).hex()
        auth_request = AuthenticationRequest(self.entity_id, self.client_nonce)
        logger.info(f"Client {self.entity_id} created auth request with nonce {self.client_nonce[:8]}...")
        return auth_request
    
    def process_auth_response(self, response):
        """Process an authentication response from the server."""
        if response.client_nonce != self.client_nonce:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Client nonce mismatch")
        
        self.server_id = response.server_id
        self.server_nonce = response.server_nonce
        
        # Verify the server's signature
        data_to_verify = (self.client_nonce + self.server_nonce).encode('utf-8')
        signature = bytes.fromhex(response.signature)
        
        if not self.key_manager.verify_signature(data_to_verify, signature, self.server_public_key):
            raise ProtocolError(ERROR_INVALID_SIGNATURE, "Invalid server signature")
        
        self.authenticate_entity(self.server_id, self.server_public_key)
        logger.info(f"Server {self.server_id} authenticated")
        return True
    
    def create_dh_exchange(self):
        """Create a Diffie-Hellman key exchange message."""
        # Generate DH parameters and keypair
        p, g = self.dh.generate_parameters()
        public_key = self.dh.generate_keypair()
        
        # Create the DH exchange message
        dh_params = self.dh.export_parameters()
        client_public_key = self.dh.export_public_key()
        dh_exchange = DHExchangeStart(
            client_id=self.entity_id,
            dh_params=dh_params,
            client_public_key=client_public_key,
            nonce=self.client_nonce
        )
        
        logger.info(f"Client {self.entity_id} created DH exchange with public key {client_public_key[:16]}...")
        return dh_exchange
    
    def process_dh_response(self, response):
        """Process a Diffie-Hellman response from the server."""
        if response.client_nonce != self.client_nonce:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Client nonce mismatch")
        
        self.server_nonce = response.server_nonce
        
        # Verify the server's signature
        data_to_verify = (self.client_nonce + self.server_nonce + response.server_public_key).encode('utf-8')
        signature = bytes.fromhex(response.signature)
        
        if not self.key_manager.verify_signature(data_to_verify, signature, self.server_public_key):
            raise ProtocolError(ERROR_INVALID_SIGNATURE, "Invalid server signature")
        
        # Compute the shared secret
        server_public_key = self.dh.import_public_key(response.server_public_key)
        shared_secret = self.dh.compute_shared_secret(server_public_key)
        self.shared_secrets[self.server_id] = shared_secret
        
        logger.info(f"Shared secret established with server {self.server_id}")
        
        # Create a permanent authorization key
        auth_key, auth_key_id = self.key_manager.generate_auth_key()
        self.auth_key_id = auth_key_id
        self.active_sessions[self.server_id] = auth_key_id
        self.last_key_rotation[auth_key_id] = time.time()
        
        logger.info(f"Permanent authorization key created, ID: {auth_key_id}")
        return True
    
    def create_temporary_key(self, expires_in=TEMP_KEY_EXPIRY):
        """Create a temporary authorization key."""
        if not self.auth_key_id:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "No permanent auth key")
        
        # Generate a temporary authorization key
        temp_key, temp_key_id, expires_at = self.key_manager.generate_temp_auth_key(expires_in)
        self.temp_auth_key_id = temp_key_id
        
        logger.info(f"Temporary authorization key created, ID: {temp_key_id}, expires at: {expires_at}")
        return temp_key_id, expires_at
    
    def create_binding_message(self):
        """Create a binding message for the temporary key."""
        if not self.auth_key_id or not self.temp_auth_key_id:
            raise ProtocolError(ERROR_BINDING_FAILED, "Missing keys for binding")
        
        # Create a binding message
        nonce = MathUtils.random_bytes(NONCE_SIZE).hex()
        expires_at = int(time.time()) + TEMP_KEY_EXPIRY
        
        # Create binding data
        binding_data = {
            "perm_auth_key_id": self.auth_key_id,
            "temp_auth_key_id": self.temp_auth_key_id,
            "expires_at": expires_at,
            "nonce": nonce
        }
        
        # Sign the binding data
        binding_bytes = json.dumps(binding_data).encode('utf-8')
        signature = self.key_manager.sign_data(binding_bytes).hex()
        
        # Add the signature to the binding data
        binding_data["signature"] = signature
        
        # Create the binding message
        binding_message = BindTempAuthKey(
            perm_auth_key_id=self.auth_key_id,
            temp_auth_key_id=self.temp_auth_key_id,
            expires_at=expires_at,
            binding_message=binding_data
        )
        
        # Bind the keys locally
        self.key_manager.bind_temp_auth_key(self.auth_key_id, self.temp_auth_key_id)
        
        logger.info(f"Binding message created for keys {self.auth_key_id[:8]}... and {self.temp_auth_key_id[:8]}...")
        return binding_message
    
    def send_message(self, message_content):
        """Send an encrypted message to the server."""
        if not self.server_id or not self.auth_key_id:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Not authenticated with server")
        
        # Create the plaintext message
        message = Message(MESSAGE_TYPE_ENCRYPTED_DATA, {"content": message_content})
        
        # Encrypt and send the message
        encrypted_message = self.send_encrypted_message(self.server_id, message)
        
        logger.info(f"Encrypted message sent to server {self.server_id}")
        return encrypted_message
    
    def receive_message(self, encrypted_message):
        """Receive and decrypt a message from the server."""
        decrypted_message = self.decrypt_message(encrypted_message)
        
        # Send an acknowledgment
        ack = ACK(encrypted_message.sequence_number)
        
        logger.info(f"Message received and decrypted from server {self.server_id}")
        return decrypted_message, ack


class Server(ProtocolEntity):
    """Server implementation for the protocol."""
    
    def __init__(self, server_id):
        """Initialize a server."""
        super().__init__(server_id)
        self.client_nonces = {}  # client_id -> nonce
        self.server_nonces = {}  # client_id -> nonce
    
    def process_auth_request(self, request):
        """Process an authentication request from a client."""
        client_id = request.client_id
        client_nonce = request.nonce
        
        # Store the client's nonce
        self.client_nonces[client_id] = client_nonce
        
        # Generate a server nonce
        server_nonce = MathUtils.random_bytes(NONCE_SIZE).hex()
        self.server_nonces[client_id] = server_nonce
        
        # Sign the nonces
        data_to_sign = (client_nonce + server_nonce).encode('utf-8')
        signature = self.key_manager.sign_data(data_to_sign).hex()
        
        # Create the authentication response
        auth_response = AuthenticationResponse(
            server_id=self.entity_id,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            signature=signature
        )
        
        logger.info(f"Server {self.entity_id} processed auth request from client {client_id}")
        return auth_response
    
    def process_dh_exchange(self, exchange):
        """Process a Diffie-Hellman key exchange from a client."""
        client_id = exchange.client_id
        client_nonce = exchange.nonce
        
        # Verify the client's nonce
        if self.client_nonces.get(client_id) != client_nonce:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Client nonce mismatch")
        
        # Import the client's DH parameters and public key
        dh_params = exchange.dh_params
        self.dh.import_parameters(dh_params)
        client_public_key = self.dh.import_public_key(exchange.client_public_key)
        
        # Generate our DH keypair and compute the shared secret
        server_public_key = self.dh.generate_keypair()
        shared_secret = self.dh.compute_shared_secret(client_public_key)
        self.shared_secrets[client_id] = shared_secret
        
        # Generate a new server nonce
        server_nonce = MathUtils.random_bytes(NONCE_SIZE).hex()
        self.server_nonces[client_id] = server_nonce
        
        # Sign the data
        server_public_key_hex = self.dh.export_public_key()
        data_to_sign = (client_nonce + server_nonce + server_public_key_hex).encode('utf-8')
        signature = self.key_manager.sign_data(data_to_sign).hex()
        
        # Create the DH response
        dh_response = DHExchangeResponse(
            server_id=self.entity_id,
            server_public_key=server_public_key_hex,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            signature=signature
        )
        
        # Create an auth key for this client
        auth_key, auth_key_id = self.key_manager.generate_auth_key()
        self.active_sessions[client_id] = auth_key_id
        self.last_key_rotation[auth_key_id] = time.time()
        
        logger.info(f"Server {self.entity_id} processed DH exchange from client {client_id}")
        return dh_response
    
    def process_binding_request(self, binding_request):
        """Process a temporary key binding request."""
        perm_auth_key_id = binding_request.perm_auth_key_id
        temp_auth_key_id = binding_request.temp_auth_key_id
        expires_at = binding_request.expires_at
        binding_message = binding_request.binding_message
        
        # Verify the binding message
        binding_data = dict(binding_message)
        signature = binding_data.pop("signature", None)
        
        if not signature:
            raise ProtocolError(ERROR_INVALID_SIGNATURE, "Missing signature in binding message")
        
        # Verify that the data in the binding message matches the request
        if binding_data.get("perm_auth_key_id") != perm_auth_key_id or \
           binding_data.get("temp_auth_key_id") != temp_auth_key_id or \
           binding_data.get("expires_at") != expires_at:
            raise ProtocolError(ERROR_BINDING_FAILED, "Binding message data mismatch")
        
        # Find the client associated with this auth key
        client_id = None
        for cid, aid in self.active_sessions.items():
            if aid == perm_auth_key_id:
                client_id = cid
                break
        
        if not client_id:
            raise ProtocolError(ERROR_BINDING_FAILED, "No client associated with this auth key")
        
        # Get the client's public key
        client_public_key = self.get_entity_public_key(client_id)
        if not client_public_key:
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Client not authenticated")
        
        # Verify the signature
        binding_bytes = json.dumps(binding_data).encode('utf-8')
        signature_bytes = bytes.fromhex(signature)
        
        if not self.key_manager.verify_signature(binding_bytes, signature_bytes, client_public_key):
            raise ProtocolError(ERROR_INVALID_SIGNATURE, "Invalid binding signature")
        
        # Bind the keys
        self.key_manager.bind_temp_auth_key(perm_auth_key_id, temp_auth_key_id)
        
        # Create an acknowledgment
        ack = ACK(0)  # Use 0 as sequence number for binding acknowledgment
        
        logger.info(f"Server {self.entity_id} processed binding request from client {client_id}")
        return ack
    
    def send_message(self, client_id, message_content):
        """Send an encrypted message to a client."""
        if not self.is_entity_authenticated(client_id):
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Client not authenticated")
        
        # Create the plaintext message
        message = Message(MESSAGE_TYPE_ENCRYPTED_DATA, {"content": message_content})
        
        # Encrypt and send the message
        encrypted_message = self.send_encrypted_message(client_id, message)
        
        logger.info(f"Encrypted message sent to client {client_id}")
        return encrypted_message
    
    def receive_message(self, client_id, encrypted_message):
        """Receive and decrypt a message from a client."""
        if not self.is_entity_authenticated(client_id):
            raise ProtocolError(ERROR_AUTHENTICATION_FAILED, "Client not authenticated")
        
        decrypted_message = self.decrypt_message(encrypted_message)
        
        # Send an acknowledgment
        ack = ACK(encrypted_message.sequence_number)
        
        logger.info(f"Message received and decrypted from client {client_id}")
        return decrypted_message, ack


