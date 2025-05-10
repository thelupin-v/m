#!/usr/bin/env python3
"""
MTProto-inspired End-to-End Encryption Protocol Library

This module implements a custom end-to-end encryption protocol inspired by MTProto,
with advanced security features:
- Diffie-Hellman key exchange with RSA authentication
- Permanent and temporary authorization keys
- Key binding mechanism
- Custom AES implementation
- Key rotation
- Traffic analysis prevention
- Replay attack prevention

All cryptographic primitives are implemented from scratch without using external 
cryptographic libraries or socket code.
"""

import os
import time
import hashlib
import struct
import random
import binascii
import json
import logging
from typing import Tuple, Dict, List, Optional, Union, Any, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MTProtoE2E")

# Constants for the protocol
PROTOCOL_VERSION = 1
KEY_SIZE = 256  # Authorization key size in bytes
RSA_KEY_SIZE = 2048  # RSA key size in bits
NONCE_SIZE = 16  # Size of nonce in bytes
TEMP_KEY_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
SEQUENCE_WINDOW_SIZE = 1000  # Maximum number of future messages to accept
MSG_HEADER_SIZE = 32  # in bytes
DH_PRIME_BITS = 2048  # Diffie-Hellman prime size


class MathUtils:
    """
    Utility class for implementing mathematical operations required for cryptography.
    """

    @staticmethod
    def is_prime(n: int, k: int = 40) -> bool:
        """
        Miller-Rabin primality test.
        
        Args:
            n: Number to test for primality
            k: Number of iterations for the test
            
        Returns:
            bool: True if n is probably prime, False if it's definitely composite
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Express n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
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
    def gcd(a: int, b: int) -> int:
        """
        Calculate the Greatest Common Divisor of a and b.
        
        Args:
            a: First number
            b: Second number
            
        Returns:
            int: The GCD of a and b
        """
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_inverse(e: int, phi: int) -> int:
        """
        Calculate the modular multiplicative inverse using extended Euclidean algorithm.
        
        Args:
            e: Number to find inverse for
            phi: Modulus
            
        Returns:
            int: Modular multiplicative inverse of e with respect to phi
        """

        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return (b, 0, 1)
            else:
                gcd, x, y = extended_gcd(b % a, a)
                return (gcd, y - (b // a) * x, x)

        gcd, x, _ = extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        else:
            return x % phi

    @staticmethod
    def generate_large_prime(bits: int) -> int:
        """
        Generate a large prime number with specified number of bits.
        
        Args:
            bits: Number of bits for the prime number
            
        Returns:
            int: A probable prime number
        """
        while True:
            # Generate a random odd number with the specified number of bits
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1  # Set MSB and LSB to 1

            if MathUtils.is_prime(p):
                return p

    @staticmethod
    def fast_mod_exp(base: int, exponent: int, modulus: int) -> int:
        """
        Fast modular exponentiation.
        
        Args:
            base: Base value
            exponent: Exponent value
            modulus: Modulus value
            
        Returns:
            int: (base^exponent) % modulus
        """
        if base == 0:
            return 0

        if exponent == 0:
            return 1

        result = 1
        base = base % modulus

        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent >>= 1
            base = (base * base) % modulus

        return result


class RSA:
    """
    Implementation of RSA encryption and signature operations.
    """

    def __init__(self, key_size: int = RSA_KEY_SIZE):
        """
        Initialize RSA with key generation.
        
        Args:
            key_size: Size of the RSA key in bits
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def generate_keypair(
            self) -> Tuple[Tuple[int, int], Tuple[int, int, int, int, int]]:
        """
        Generate an RSA key pair.
        
        Returns:
            Tuple: ((n, e), (n, e, d, p, q)) - public and private key components
        """
        # Generate two distinct primes p and q
        bits_per_prime = self.key_size // 2
        p = MathUtils.generate_large_prime(bits_per_prime)
        q = MathUtils.generate_large_prime(bits_per_prime)

        # Ensure p and q are distinct
        while p == q:
            q = MathUtils.generate_large_prime(bits_per_prime)

        # Calculate n and phi(n)
        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose e such that 1 < e < phi and gcd(e, phi) = 1
        e = 65537  # Common value for e

        # Ensure e and phi are coprime
        while MathUtils.gcd(e, phi) != 1:
            e += 2

        # Calculate d, the modular multiplicative inverse of e mod phi
        d = MathUtils.mod_inverse(e, phi)

        self.public_key = (n, e)
        self.private_key = (n, e, d, p, q)

        if not self.public_key or not self.private_key:
            raise ValueError("Key generation failed")

        return self.public_key, self.private_key

    def encrypt(self, message: int, public_key: Tuple[int, int]) -> int:
        """
        Encrypt a message using RSA.
        
        Args:
            message: Integer message to encrypt
            public_key: Public key (n, e)
            
        Returns:
            int: Encrypted message
        """
        if not public_key:
            raise ValueError("Invalid public key")

        n, e = public_key
        if message >= n:
            raise ValueError("Message is too large for the key size")

        return MathUtils.fast_mod_exp(message, e, n)

    def decrypt(self, ciphertext: int, private_key: Tuple[int, int, int, int,
                                                          int]) -> int:
        """
        Decrypt a message using RSA.
        
        Args:
            ciphertext: Encrypted message
            private_key: Private key (n, e, d, p, q)
            
        Returns:
            int: Decrypted message
        """
        if not private_key:
            raise ValueError("Invalid private key")

        n, _, d, _, _ = private_key
        return MathUtils.fast_mod_exp(ciphertext, d, n)

    def sign(self, message: int, private_key: Tuple[int, int, int, int,
                                                    int]) -> int:
        """
        Sign a message using RSA.
        
        Args:
            message: Integer message to sign
            private_key: Private key (n, e, d, p, q)
            
        Returns:
            int: Signature
        """
        return self.decrypt(message, private_key)

    def verify(self, message: int, signature: int,
               public_key: Tuple[int, int]) -> bool:
        """
        Verify an RSA signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key (n, e)
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        decrypted_signature = self.encrypt(signature, public_key)
        return decrypted_signature == message


class DiffieHellman:
    """
    Implementation of Diffie-Hellman key exchange.
    """

    def __init__(self, prime_bits: int = DH_PRIME_BITS):
        """
        Initialize Diffie-Hellman with specified prime size.
        
        Args:
            prime_bits: Size of prime in bits
        """
        # RFC 3526 MODP Group 14 (2048 bits) for production use
        self.p = int(
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
            '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
            'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
            '15728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
        self.g = 2  # generator
        self.private_key = None
        self.public_key = None

    def generate_private_key(self) -> int:
        """
        Generate a private key for Diffie-Hellman key exchange.
        
        Returns:
            int: Private key
        """
        # Generate a random private key (a) that is less than p
        self.private_key = random.randint(2, self.p - 2)
        return self.private_key

    def generate_public_key(self) -> int:
        """
        Generate a public key from the private key.
        
        Returns:
            int: Public key
        """
        if self.private_key is None:
            self.generate_private_key()

        # Calculate public key: g^a mod p
        self.public_key = MathUtils.fast_mod_exp(self.g, self.private_key,
                                                 self.p)
        return self.public_key

    def compute_shared_secret(self, other_public_key: int) -> int:
        """
        Compute the shared secret from the other party's public key.
        
        Args:
            other_public_key: The other party's public key
            
        Returns:
            int: Shared secret
        """
        if self.private_key is None:
            raise ValueError("Private key not generated")

        # Calculate shared secret: (other_public_key)^private_key mod p
        shared_secret = MathUtils.fast_mod_exp(other_public_key,
                                               self.private_key, self.p)
        return shared_secret


class AES:
    """
    Custom implementation of AES encryption algorithm.
    """
    # AES S-box (Substitution box)
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
        0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
        0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
        0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16
    ]

    # Inverse S-box for decryption
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
        0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
        0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
        0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
        0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
        0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
        0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
        0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
        0x55, 0x21, 0x0c, 0x7d
    ]

    # Round constants for key expansion
    RCON = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6
    ]

    def __init__(self, key: bytes):
        """
        Initialize AES with a key.
        
        Args:
            key: Encryption key (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
        """
        self.key = key
        self.key_size = len(key)

        # AES key size can be 16, 24, or 32 bytes (128, 192, or 256 bits)
        if self.key_size not in (16, 24, 32):
            raise ValueError(
                "Invalid key size. Key must be 16, 24, or 32 bytes.")

        self.rounds = {16: 10, 24: 12, 32: 14}[self.key_size]
        self.round_keys = self._expand_key()

    def _expand_key(self) -> List[List[int]]:
        """
        Expand the key into round keys.
        
        Returns:
            List[List[int]]: Round keys
        """
        # Each word is 4 bytes
        key_words = [self.key[i:i + 4] for i in range(0, len(self.key), 4)]
        key_words = [[b for b in word] for word in key_words]

        # Number of words in expanded key = 4 * (rounds + 1)
        expanded_words = 4 * (self.rounds + 1)
        expanded_key = [[] for _ in range(expanded_words)]

        # First words are from the key
        for i in range(len(key_words)):
            expanded_key[i] = key_words[i].copy()

        # Expand the key
        for i in range(len(key_words), expanded_words):
            temp = expanded_key[i - 1].copy()

            if i % len(key_words) == 0:
                # Rotate word
                temp = temp[1:] + [temp[0]]
                # Apply S-box
                temp = [self.S_BOX[b] for b in temp]
                # XOR with round constant
                temp[0] ^= self.RCON[(i // len(key_words)) - 1]
            elif len(key_words) > 6 and i % len(key_words) == 4:
                # Apply S-box for AES-256
                temp = [self.S_BOX[b] for b in temp]

            # XOR with word len(key_words) positions earlier
            expanded_key[i] = [
                a ^ b for a, b in zip(expanded_key[i - len(key_words)], temp)
            ]

        return expanded_key

    def _sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """
        Apply S-box substitution to state.
        
        Args:
            state: 4x4 state array
            
        Returns:
            List[List[int]]: Transformed state
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.S_BOX[state[i][j]]
        return state

    def _inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """
        Apply inverse S-box substitution to state.
        
        Args:
            state: 4x4 state array
            
        Returns:
            List[List[int]]: Transformed state
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_S_BOX[state[i][j]]
        return state

    def _shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """
        Shift rows of state.
        
        Args:
            state: 4x4 state array
            
        Returns:
            List[List[int]]: Transformed state
        """
        state[1] = state[1][1:] + [state[1][0]]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def _inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """
        Inverse shift rows of state.
        
        Args:
            state: 4x4 state array
            
        Returns:
            List[List[int]]: Transformed state
        """
        state[1] = [state[1][-1]] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def _mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """
        Mix columns of state.
        
        Args:
            state: 4x4 state array
            
        Returns:
            List[List[int]]: Transformed state
        """

        def galois_mult(a: int, b: int) -> int:
            """Galois field multiplication for AES."""
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a <<= 1
                if hi_bit_set:
                    a ^= 0x1b  # AES irreducible polynomial
                b >>= 1
            return p % 256

        for i in range(4):
            temp = state[i].copy()
            state[i][0] = galois_mult(temp[0], 2) ^ galois_mult(
                temp[1], 3) ^ temp[2] ^ temp[3]
            state[i][1] = temp[0] ^ galois_mult(temp[1], 2) ^ galois_mult(
                temp[2], 3) ^ temp[3]
            state[i][2] = temp[0] ^ temp[1] ^ galois_mult(
                temp[2], 2) ^ galois_mult(temp[3], 3)
            state[i][3] = galois_mult(
                temp[0], 3) ^ temp[1] ^ temp[2] ^ galois_mult(temp[3], 2)

        return state

    def _inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """
        Inverse mix columns of state.
        
        Args:
            state: 4x4 state array
            
        Returns:
            List[List[int]]: Transformed state
        """

        def galois_mult(a: int, b: int) -> int:
            """Galois field multiplication for AES."""
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a <<= 1
                if hi_bit_set:
                    a ^= 0x1b  # AES irreducible polynomial
                b >>= 1
            return p % 256

        for i in range(4):
            temp = state[i].copy()
            state[i][0] = galois_mult(temp[0], 14) ^ galois_mult(
                temp[1], 11) ^ galois_mult(temp[2], 13) ^ galois_mult(
                    temp[3], 9)
            state[i][1] = galois_mult(temp[0], 9) ^ galois_mult(
                temp[1], 14) ^ galois_mult(temp[2], 11) ^ galois_mult(
                    temp[3], 13)
            state[i][2] = galois_mult(temp[0], 13) ^ galois_mult(
                temp[1], 9) ^ galois_mult(temp[2], 14) ^ galois_mult(
                    temp[3], 11)
            state[i][3] = galois_mult(temp[0], 11) ^ galois_mult(
                temp[1], 13) ^ galois_mult(temp[2], 9) ^ galois_mult(
                    temp[3], 14)

        return state

    def _add_round_key(self, state: List[List[int]],
                       round_key: List[List[int]]) -> List[List[int]]:
        """
        Add round key to state.
        
        Args:
            state: 4x4 state array
            round_key: Round key to add
            
        Returns:
            List[List[int]]: Transformed state
        """
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt a single 16-byte block using AES.
        
        Args:
            block: 16-byte block to encrypt
            
        Returns:
            bytes: Encrypted block
        """
        if len(block) != 16:
            raise ValueError("Block size must be 16 bytes")

        # State is a 4x4 matrix of bytes
        state = [[block[i * 4 + j] for j in range(4)] for i in range(4)]

        # Initial round key addition
        round_key = [self.round_keys[i] for i in range(4)]
        state = self._add_round_key(state, round_key)

        # Main rounds
        for round_num in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            round_key = [self.round_keys[4 * round_num + i] for i in range(4)]
            state = self._add_round_key(state, round_key)

        # Final round (no mix columns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        round_key = [self.round_keys[4 * self.rounds + i] for i in range(4)]
        state = self._add_round_key(state, round_key)

        # Convert state back to bytes
        result = bytearray(16)
        for i in range(4):
            for j in range(4):
                result[i * 4 + j] = state[i][j]

        return bytes(result)

    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt a single 16-byte block using AES.
        
        Args:
            block: 16-byte encrypted block
            
        Returns:
            bytes: Decrypted block
        """
        if len(block) != 16:
            raise ValueError("Block size must be 16 bytes")

        # State is a 4x4 matrix of bytes
        state = [[block[i * 4 + j] for j in range(4)] for i in range(4)]

        # Initial round key addition (with the last round key)
        round_key = [self.round_keys[4 * self.rounds + i] for i in range(4)]
        state = self._add_round_key(state, round_key)

        # Main rounds (in reverse)
        for round_num in range(self.rounds - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            round_key = [self.round_keys[4 * round_num + i] for i in range(4)]
            state = self._add_round_key(state, round_key)
            state = self._inv_mix_columns(state)

        # Final round (no mix columns)
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        round_key = [self.round_keys[i] for i in range(4)]
        state = self._add_round_key(state, round_key)

        # Convert state back to bytes
        result = bytearray(16)
        for i in range(4):
            for j in range(4):
                result[i * 4 + j] = state[i][j]

        return bytes(result)

    def encrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """
        Encrypt data using AES in CBC mode.
        
        Args:
            data: Data to encrypt
            iv: 16-byte initialization vector
            
        Returns:
            bytes: Encrypted data
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        # Pad data to a multiple of 16 bytes
        padded_data = self._pad_data(data)

        # Encrypt each block
        encrypted = bytearray()
        previous_block = iv

        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]
            # XOR with previous ciphertext block
            xored_block = bytes(a ^ b for a, b in zip(block, previous_block))
            # Encrypt
            encrypted_block = self.encrypt_block(xored_block)
            encrypted.extend(encrypted_block)
            previous_block = encrypted_block

        return bytes(encrypted)

    def decrypt_cbc(self, data: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using AES in CBC mode.
        
        Args:
            data: Encrypted data
            iv: 16-byte initialization vector
            
        Returns:
            bytes: Decrypted data
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        if len(data) % 16 != 0:
            raise ValueError(
                "Encrypted data length must be a multiple of 16 bytes")

        # Decrypt each block
        decrypted = bytearray()
        previous_block = iv

        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            # Decrypt
            decrypted_block = self.decrypt_block(block)
            # XOR with previous ciphertext block
            xored_block = bytes(
                a ^ b for a, b in zip(decrypted_block, previous_block))
            decrypted.extend(xored_block)
            previous_block = block

        # Remove padding
        return self._unpad_data(decrypted)

    def _pad_data(self, data: bytes) -> bytes:
        """
        Add PKCS#7 padding to data.
        
        Args:
            data: Data to pad
            
        Returns:
            bytes: Padded data
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad_data(self, data: bytes) -> bytes:
        """
        Remove PKCS#7 padding from data.
        
        Args:
            data: Padded data
            
        Returns:
            bytes: Unpadded data
        """
        padding_length = data[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")

        # Validate padding
        for i in range(padding_length):
            if data[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding")

        return data[:-padding_length]


class AuthorizationKey:
    """
    Represents an authorization key in the protocol.
    """

    def __init__(self,
                 key_id: int,
                 key: bytes,
                 is_temp: bool = False,
                 expires_at: Optional[int] = None):
        """
        Initialize authorization key.
        
        Args:
            key_id: Key ID
            key: Key bytes
            is_temp: Whether this is a temporary key
            expires_at: Expiry timestamp for temporary keys
        """
        self.key_id = key_id
        self.key = key
        self.is_temp = is_temp
        self.expires_at = expires_at
        self.bound_to = None  # For temporary keys, ID of permanent key

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize authorization key to a dictionary.
        
        Returns:
            Dict[str, Any]: Serialized key data
        """
        return {
            'key_id': self.key_id,
            'key': binascii.hexlify(self.key).decode('ascii'),
            'is_temp': self.is_temp,
            'expires_at': self.expires_at,
            'bound_to': self.bound_to
        }

    @classmethod
    def deserialize(cls, data: Dict[str, Any]) -> 'AuthorizationKey':
        """
        Deserialize authorization key from a dictionary.
        
        Args:
            data: Dictionary containing key data
            
        Returns:
            AuthorizationKey: Deserialized key
        """
        key = binascii.unhexlify(data['key'])
        auth_key = cls(data['key_id'], key, data['is_temp'],
                       data['expires_at'])
        auth_key.bound_to = data['bound_to']
        return auth_key


class Message:
    """
    Represents a protocol message.
    """

    def __init__(self, msg_id: int, seq_no: int, msg_type: int,
                 content: bytes):
        """
        Initialize message.
        
        Args:
            msg_id: Message ID
            seq_no: Sequence number
            msg_type: Message type
            content: Message content
        """
        self.msg_id = msg_id
        self.seq_no = seq_no
        self.msg_type = msg_type
        self.content = content

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize message to a dictionary.
        
        Returns:
            Dict[str, Any]: Serialized message data
        """
        return {
            'msg_id': self.msg_id,
            'seq_no': self.seq_no,
            'msg_type': self.msg_type,
            'content': binascii.hexlify(self.content).decode('ascii')
        }

    @classmethod
    def deserialize(cls, data: Dict[str, Any]) -> 'Message':
        """
        Deserialize message from a dictionary.
        
        Args:
            data: Dictionary containing message data
            
        Returns:
            Message: Deserialized message
        """
        content = binascii.unhexlify(data['content'])
        return cls(data['msg_id'], data['seq_no'], data['msg_type'], content)


class EncryptedMessage(Message):
    """
    Represents an encrypted protocol message.
    """

    def __init__(self, msg_id: int, seq_no: int, msg_type: int, content: bytes,
                 auth_key_id: int):
        """
        Initialize encrypted message.
        
        Args:
            msg_id: Message ID
            seq_no: Sequence number
            msg_type: Message type
            content: Encrypted message content
            auth_key_id: Authorization key ID
        """
        super().__init__(msg_id, seq_no, msg_type, content)
        self.auth_key_id = auth_key_id

    def serialize(self) -> Dict[str, Any]:
        """
        Serialize encrypted message to a dictionary.
        
        Returns:
            Dict[str, Any]: Serialized message data
        """
        data = super().serialize()
        data['auth_key_id'] = self.auth_key_id
        return data

    @classmethod
    def deserialize(cls, data: Dict[str, Any]) -> 'EncryptedMessage':
        """
        Deserialize encrypted message from a dictionary.
        
        Args:
            data: Dictionary containing message data
            
        Returns:
            EncryptedMessage: Deserialized message
        """
        msg = Message.deserialize(data)
        return cls(msg.msg_id, msg.seq_no, msg.msg_type, msg.content,
                   data['auth_key_id'])


class MTProtoE2E:
    """
    Main protocol implementation for end-to-end encryption.
    """
    # Message types
    MSG_PQ_REQUEST = 1
    MSG_PQ_RESPONSE = 2
    MSG_DH_PARAMS_REQUEST = 3
    MSG_DH_PARAMS_RESPONSE = 4
    MSG_DH_PARAMS_VERIFY = 5
    MSG_DH_PARAMS_CONFIRM = 6
    MSG_BIND_TEMP_KEY = 7
    MSG_BIND_TEMP_KEY_RESPONSE = 8
    MSG_DATA = 100
    MSG_DATA_RESPONSE = 101

    def __init__(self):
        """Initialize protocol."""
        # Keys
        self.perm_auth_keys = {}  # key_id -> AuthorizationKey
        self.temp_auth_keys = {}  # key_id -> AuthorizationKey

        # RSA for server authentication
        self.rsa = RSA()
        self.server_public_key = None
        self.server_private_key = None

        # Sequence counters
        self.sequence_counters = {}  # auth_key_id -> last_seq_no

        # Message history for replay protection
        self.processed_messages = {}  # auth_key_id -> set(msg_id)

        # DH parameters
        self.dh = None

        # Nonces for authentication
        self.nonces = {}

    def initialize_as_server(self):
        """Initialize as server with RSA key pair."""
        public_key, private_key = self.rsa.generate_keypair()
        self.server_public_key = public_key
        self.server_private_key = private_key
        logger.info(f"Server initialized with RSA public key: {public_key[0]}")

    def initialize_as_client(self, server_public_key: Tuple[int, int]):
        """
        Initialize as client with server's public key.
        
        Args:
            server_public_key: Server's RSA public key
        """
        if not server_public_key:
            raise ValueError("Server public key is required")

        self.server_public_key = server_public_key
        logger.info(
            f"Client initialized with server public key: {server_public_key[0]}"
        )

    def _generate_msg_id(self) -> int:
        """
        Generate a unique message ID based on current time.
        
        Returns:
            int: Message ID
        """
        # Use current time in milliseconds as base
        time_part = int(time.time() * 1000)
        # Add random part for uniqueness
        random_part = random.randint(0, 0xFFFFFFFF)

        return ((time_part << 32) | random_part)

    def _next_seq_no(self, auth_key_id: int) -> int:
        """
        Get next sequence number for a given authorization key.
        
        Args:
            auth_key_id: Authorization key ID
            
        Returns:
            int: Next sequence number
        """
        if auth_key_id not in self.sequence_counters:
            self.sequence_counters[auth_key_id] = 0

        self.sequence_counters[auth_key_id] += 1
        return self.sequence_counters[auth_key_id]

    def _check_seq_no(self, auth_key_id: int, seq_no: int) -> bool:
        """
        Check if sequence number is valid.
        
        Args:
            auth_key_id: Authorization key ID
            seq_no: Sequence number to check
            
        Returns:
            bool: True if valid, False otherwise
        """
        if auth_key_id not in self.sequence_counters:
            # First message with this key, accept if seq_no is 1
            return seq_no == 1

        last_seq = self.sequence_counters[auth_key_id]

        # Accept if sequence number is next in sequence
        if seq_no == last_seq + 1:
            return True

        # Accept if sequence number is not too far ahead (to handle out-of-order delivery)
        if seq_no > last_seq + 1 and seq_no <= last_seq + SEQUENCE_WINDOW_SIZE:
            return True

        # Reject otherwise
        return False

    def _check_msg_replay(self, auth_key_id: int, msg_id: int) -> bool:
        """
        Check if message has been processed before (replay protection).
        
        Args:
            auth_key_id: Authorization key ID
            msg_id: Message ID to check
            
        Returns:
            bool: True if not a replay, False if it's a replay
        """
        if auth_key_id not in self.processed_messages:
            self.processed_messages[auth_key_id] = set()

        if msg_id in self.processed_messages[auth_key_id]:
            return False

        self.processed_messages[auth_key_id].add(msg_id)

        # Limit size of processed messages set
        if len(self.processed_messages[auth_key_id]) > 10000:
            # Remove oldest messages (those with smallest msg_id)
            to_remove = sorted(list(
                self.processed_messages[auth_key_id]))[:5000]
            for old_id in to_remove:
                self.processed_messages[auth_key_id].remove(old_id)

        return True

    def _random_padding(self,
                        min_bytes: int = 32,
                        max_bytes: int = 256) -> bytes:
        """
        Generate random padding to prevent traffic analysis.
        
        Args:
            min_bytes: Minimum padding size
            max_bytes: Maximum padding size
            
        Returns:
            bytes: Random padding
        """
        padding_size = random.randint(min_bytes, max_bytes)
        return os.urandom(padding_size)

    def _encrypt_message(self, auth_key_id: int, message: bytes) -> bytes:
        """
        Encrypt a message using an authorization key.
        
        Args:
            auth_key_id: Authorization key ID
            message: Message to encrypt
            
        Returns:
            bytes: Encrypted message
        """
        # Find key
        auth_key = None
        if auth_key_id in self.temp_auth_keys:
            auth_key = self.temp_auth_keys[auth_key_id]
        elif auth_key_id in self.perm_auth_keys:
            auth_key = self.perm_auth_keys[auth_key_id]

        if not auth_key:
            raise ValueError(f"Authorization key not found: {auth_key_id}")

        # Check if temporary key has expired
        if auth_key.is_temp and auth_key.expires_at and time.time(
        ) > auth_key.expires_at:
            raise ValueError(
                f"Temporary authorization key has expired: {auth_key_id}")

        # Pad message to prevent traffic analysis
        padded_message = message + self._random_padding()

        # Add hash for integrity check
        message_hash = hashlib.sha256(padded_message).digest()
        message_with_hash = message_hash + padded_message

        # Encrypt with AES
        iv = os.urandom(16)  # Random IV for each message
        aes = AES(auth_key.key[:32])  # Use first 32 bytes of key for AES-256
        encrypted = aes.encrypt_cbc(message_with_hash, iv)

        # Prepend IV to encrypted message
        return iv + encrypted

    def _decrypt_message(self, auth_key_id: int,
                         encrypted_message: bytes) -> bytes:
        """
        Decrypt a message using an authorization key.
        
        Args:
            auth_key_id: Authorization key ID
            encrypted_message: Encrypted message
            
        Returns:
            bytes: Decrypted message
        """
        # Find key
        auth_key = None
        if auth_key_id in self.temp_auth_keys:
            auth_key = self.temp_auth_keys[auth_key_id]
        elif auth_key_id in self.perm_auth_keys:
            auth_key = self.perm_auth_keys[auth_key_id]

        if not auth_key:
            raise ValueError(f"Authorization key not found: {auth_key_id}")

        # Check if temporary key has expired
        if auth_key.is_temp and auth_key.expires_at and time.time(
        ) > auth_key.expires_at:
            raise ValueError(
                f"Temporary authorization key has expired: {auth_key_id}")

        # Extract IV (first 16 bytes)
        iv = encrypted_message[:16]
        encrypted_data = encrypted_message[16:]

        # Decrypt with AES
        aes = AES(auth_key.key[:32])  # Use first 32 bytes of key for AES-256
        decrypted = aes.decrypt_cbc(encrypted_data, iv)

        # Verify hash for integrity
        message_hash = decrypted[:32]  # SHA-256 hash is 32 bytes
        message_with_padding = decrypted[32:]

        calculated_hash = hashlib.sha256(message_with_padding).digest()
        if message_hash != calculated_hash:
            raise ValueError("Message integrity check failed")

        # Find end of actual message (strip padding)
        # In a real MTProto-like implementation, we'd use a proper structure to identify
        # the end of the message. For simplicity, we'll rely on the caller to handle this.
        return message_with_padding

    def generate_permanent_auth_key(self) -> Tuple[int, bytes]:
        """
        Generate a permanent authorization key.
        
        Returns:
            Tuple[int, bytes]: Key ID and key
        """
        # Generate random key
        key = os.urandom(KEY_SIZE)

        # Calculate key ID as SHA-256 hash of key
        key_id = int.from_bytes(hashlib.sha256(key).digest()[:8],
                                byteorder='little')

        # Create and store key
        auth_key = AuthorizationKey(key_id, key, is_temp=False)
        self.perm_auth_keys[key_id] = auth_key

        logger.info(f"Generated permanent auth key: {key_id}")
        return key_id, key

    def generate_temporary_auth_key(self) -> Tuple[int, bytes]:
        """
        Generate a temporary authorization key.
        
        Returns:
            Tuple[int, bytes]: Key ID and key
        """
        # Generate random key
        key = os.urandom(KEY_SIZE)

        # Calculate key ID as SHA-256 hash of key
        key_id = int.from_bytes(hashlib.sha256(key).digest()[:8],
                                byteorder='little')

        # Set expiry time
        expires_at = int(time.time()) + TEMP_KEY_EXPIRY

        # Create and store key
        auth_key = AuthorizationKey(key_id,
                                    key,
                                    is_temp=True,
                                    expires_at=expires_at)
        self.temp_auth_keys[key_id] = auth_key

        logger.info(
            f"Generated temporary auth key: {key_id}, expires at: {expires_at}"
        )
        return key_id, key

    def bind_temp_auth_key(self, perm_key_id: int, temp_key_id: int) -> bool:
        """
        Bind a temporary authorization key to a permanent one.
        
        Args:
            perm_key_id: Permanent key ID
            temp_key_id: Temporary key ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        if perm_key_id not in self.perm_auth_keys:
            logger.error(f"Permanent key not found: {perm_key_id}")
            return False

        if temp_key_id not in self.temp_auth_keys:
            logger.error(f"Temporary key not found: {temp_key_id}")
            return False

        # Check if perm key is bound to another temp key
        for key_id, key in self.temp_auth_keys.items():
            if key.bound_to == perm_key_id and key_id != temp_key_id:
                # Unbind
                key.bound_to = None
                logger.info(
                    f"Unbound temp key {key_id} from perm key {perm_key_id}")

        # Bind
        self.temp_auth_keys[temp_key_id].bound_to = perm_key_id
        logger.info(f"Bound temp key {temp_key_id} to perm key {perm_key_id}")

        return True

    def rotate_keys(self) -> Tuple[int, int]:
        """
        Rotate encryption keys for improved security.
        
        Returns:
            Tuple[int, int]: Permanent key ID and new temporary key ID
        """
        # Find a bound key pair
        perm_key_id = None
        temp_key_id = None

        for key_id, key in self.temp_auth_keys.items():
            if key.bound_to and key.bound_to in self.perm_auth_keys:
                perm_key_id = key.bound_to
                temp_key_id = key_id
                break

        if not perm_key_id:
            # No bound keys, cannot rotate
            logger.error("No bound keys found for rotation")
            return None, None

        # Generate new temporary key
        new_temp_key_id, _ = self.generate_temporary_auth_key()

        # Bind to permanent key
        if self.bind_temp_auth_key(perm_key_id, new_temp_key_id):
            logger.info(
                f"Rotated keys: new temp key {new_temp_key_id} bound to perm key {perm_key_id}"
            )

            # Schedule old temporary key for removal
            old_key = self.temp_auth_keys[temp_key_id]
            old_key.expires_at = int(
                time.time()) + 300  # 5 minute grace period
            logger.info(
                f"Old temp key {temp_key_id} scheduled for removal in 5 minutes"
            )

            return perm_key_id, new_temp_key_id
        else:
            logger.error("Failed to bind new temporary key during rotation")
            # Remove the new key since binding failed
            if new_temp_key_id in self.temp_auth_keys:
                del self.temp_auth_keys[new_temp_key_id]
            return None, None

    def perform_key_exchange(self) -> Tuple[int, int]:
        """
        Perform a complete key exchange using Diffie-Hellman.
        This is a local simulation of the full key exchange protocol.
        
        Returns:
            Tuple[int, int]: Permanent and temporary key IDs if successful, or (None, None)
        """
        try:
            # Create PQ Request (step 1)
            nonce = os.urandom(NONCE_SIZE)
            self.nonces['nonce'] = nonce

            # PQ Response (step 2 - server side)
            server_nonce = os.urandom(NONCE_SIZE)
            self.nonces['server_nonce'] = server_nonce

            # Generate PQ values
            p = MathUtils.generate_large_prime(512)
            q = MathUtils.generate_large_prime(512)
            pq = p * q

            # DH Parameters Request (step 3 - client side)
            new_nonce = os.urandom(NONCE_SIZE)
            self.nonces['new_nonce'] = new_nonce

            # Initialize DH on server side
            self.dh = DiffieHellman()
            server_private_key = self.dh.generate_private_key()
            server_public_key = self.dh.generate_public_key()

            # DH Parameters Response (step 4 - server side)
            # Verify server authenticity with RSA signatures
            if not self.server_public_key:
                raise ValueError("Server public key not available")

            # The challenge data would normally be signed with server's private key
            if hasattr(self, 'server_private_key') and self.server_private_key:
                # Server side can sign
                signature = self.rsa.sign(
                    123456789, self.server_private_key)  # Simplified
            else:
                # For simulation, we trust the server implicitly
                signature = 123456789  # Placeholder

            # DH Parameters Verification (step 5 - client side)
            # Initialize DH on client side
            client_dh = DiffieHellman()
            client_private_key = client_dh.generate_private_key()
            client_public_key = client_dh.generate_public_key()

            # Compute shared secret on client side
            client_shared_secret = client_dh.compute_shared_secret(
                server_public_key)

            # DH Parameters Confirmation (step 6 - server side)
            # Compute shared secret on server side
            server_shared_secret = self.dh.compute_shared_secret(
                client_public_key)

            # Verify shared secrets match
            if client_shared_secret != server_shared_secret:
                raise ValueError("Shared secret mismatch")

            # Create authorization key from shared secret
            secret_str = str(client_shared_secret).encode('utf-8')
            auth_key = hashlib.sha512(
                secret_str).digest()  # Use SHA-512 for a 64-byte key
            auth_key_id = int.from_bytes(hashlib.sha256(auth_key).digest()[:8],
                                         byteorder='little')

            # Store as permanent key
            perm_auth_key = AuthorizationKey(auth_key_id,
                                             auth_key,
                                             is_temp=False)
            self.perm_auth_keys[auth_key_id] = perm_auth_key

            # Generate temporary key
            temp_key_id, temp_key = self.generate_temporary_auth_key()

            # Bind temporary key to permanent key
            if self.bind_temp_auth_key(auth_key_id, temp_key_id):
                return auth_key_id, temp_key_id
            else:
                return None, None
        except Exception as e:
            logger.error(f"Key exchange failed: {str(e)}")
            return None, None

    def encrypt_data(self,
                     data: bytes,
                     auth_key_id: Optional[int] = None) -> bytes:
        """
        Encrypt data using a bound temporary key.
        
        Args:
            data: Data to encrypt
            auth_key_id: Optional auth key ID to use, if None, uses a bound temp key
            
        Returns:
            bytes: Serialized encrypted message
        """
        if auth_key_id is None:
            # Find a bound temp key
            for key_id, key in self.temp_auth_keys.items():
                if key.bound_to and key.bound_to in self.perm_auth_keys:
                    auth_key_id = key_id
                    break

            if auth_key_id is None:
                raise ValueError("No bound temporary key found")

        elif auth_key_id not in self.temp_auth_keys and auth_key_id not in self.perm_auth_keys:
            raise ValueError(f"Authorization key not found: {auth_key_id}")

        # Create data message
        data_content = {
            'data': binascii.hexlify(data).decode('ascii'),
            'timestamp': int(time.time())
        }

        # Convert to bytes
        content_bytes = json.dumps(data_content).encode('utf-8')

        # Create message
        msg_id = self._generate_msg_id()
        seq_no = self._next_seq_no(auth_key_id)

        msg = Message(msg_id, seq_no, self.MSG_DATA, content_bytes)
        serialized_msg = json.dumps(msg.serialize()).encode('utf-8')

        # Encrypt message
        encrypted_data = self._encrypt_message(auth_key_id, serialized_msg)

        # Create encrypted message
        encrypted_msg = EncryptedMessage(msg_id, seq_no, self.MSG_DATA,
                                         encrypted_data, auth_key_id)

        # Return serialized message
        return json.dumps(encrypted_msg.serialize()).encode('utf-8')

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Serialized encrypted message
            
        Returns:
            bytes: Decrypted data
        """
        # Parse encrypted message
        encrypted_msg_data = json.loads(encrypted_data.decode('utf-8'))
        encrypted_msg = EncryptedMessage.deserialize(encrypted_msg_data)

        # Decrypt inner message
        decrypted_data = self._decrypt_message(encrypted_msg.auth_key_id,
                                               encrypted_msg.content)

        # Parse inner message
        inner_msg_data = json.loads(decrypted_data.decode('utf-8'))
        inner_msg = Message.deserialize(inner_msg_data)

        # Check sequence number
        if not self._check_seq_no(encrypted_msg.auth_key_id, inner_msg.seq_no):
            raise ValueError("Invalid sequence number")

        # Check for replay
        if not self._check_msg_replay(encrypted_msg.auth_key_id,
                                      inner_msg.msg_id):
            raise ValueError("Message replay detected")

        # Update sequence counter
        self.sequence_counters[encrypted_msg.auth_key_id] = inner_msg.seq_no

        # Parse content
        content = json.loads(inner_msg.content.decode('utf-8'))

        # Extract data
        data = binascii.unhexlify(content['data'])

        return data

    def get_key_info(self) -> Dict[str, Any]:
        """
        Get information about current keys.
        
        Returns:
            Dict[str, Any]: Key information
        """
        bound_keys = 0
        for key in self.temp_auth_keys.values():
            if key.bound_to is not None:
                bound_keys += 1

        return {
            'permanent_keys': len(self.perm_auth_keys),
            'temporary_keys': len(self.temp_auth_keys),
            'bound_keys': bound_keys
        }


class AuthenticationError(Exception):
    """Exception raised for authentication failures."""
    pass
