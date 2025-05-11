import time
from px import RSA, MathUtils

def measure_execution_time(func, *args, **kwargs):
    """Measure the execution time of a function."""
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    return result, end_time - start_time

def test_rsa_timing():
    """Test for timing variations in RSA encryption/decryption."""
    rsa = RSA()
    public_key, private_key = rsa.generate_keys()

    # Generate test messages
    message_small = MathUtils.random_bytes(16)  # Small message
    message_large = MathUtils.random_bytes(256)  # Large message (close to key size)

    # Measure encryption time for small and large messages
    _, time_small = measure_execution_time(rsa.encrypt, message_small, public_key)
    _, time_large = measure_execution_time(rsa.encrypt, message_large, public_key)

    print(f"Encryption time (small message): {time_small:.6f} seconds")
    print(f"Encryption time (large message): {time_large:.6f} seconds")

    # Measure decryption time for small and large messages
    ciphertext_small = rsa.encrypt(message_small, public_key)
    ciphertext_large = rsa.encrypt(message_large, public_key)

    _, time_decrypt_small = measure_execution_time(rsa.decrypt, ciphertext_small, private_key)
    _, time_decrypt_large = measure_execution_time(rsa.decrypt, ciphertext_large, private_key)

    print(f"Decryption time (small message): {time_decrypt_small:.6f} seconds")
    print(f"Decryption time (large message): {time_decrypt_large:.6f} seconds")

    # Analyze timing differences
    if abs(time_small - time_large) > 0.001 or abs(time_decrypt_small - time_decrypt_large) > 0.001:
        print("Potential timing vulnerability detected!")
    else:
        print("No significant timing differences detected.")

if __name__ == "__main__":
    test_rsa_timing()
