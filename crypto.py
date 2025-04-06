from hashlib import pbkdf2_hmac, sha1, md5
from Crypto.Cipher import AES
from Crypto.Hash import HMAC

def calc_pmk(passphrase, ssid):
    # PBKDF2 to calculate the PMK
    pmk = pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    return pmk

def calc_ptk(pmk, aa, spa, anonce, snonce):
    pke = b"Pairwise key expansion" + min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    ptk = b""
    for i in range(4):
        hmac_sha1 = HMAC.new(pmk, digestmod=sha1)
        hmac_sha1.update(pke + bytes([i]))
        ptk += hmac_sha1.digest()[:20]
    return ptk

def calc_mic(ptk, data, keyver):
    if keyver == 1:
        hmac_md5 = HMAC.new(ptk[:16], digestmod=md5)
        hmac_md5.update(data)
        return hmac_md5.digest()
    elif keyver == 2:
        hmac_sha1 = HMAC.new(ptk[:16], digestmod=sha1)
        hmac_sha1.update(data)
        return hmac_sha1.digest()[:16]

def encrypt_ccmp(data, key, nonce):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    ciphertext, mac = cipher.encrypt_and_digest(data)
    return ciphertext + mac

def decrypt_ccmp(data, key, nonce):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    ciphertext = data[:-8]
    mac = data[-8:]
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, mac)
        return decrypted_data
    except ValueError:
        return None
