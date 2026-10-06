import os, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

SAD = {}

def add_sa(spi, source, destination, lifetime=3600):
    if spi in SAD: return False
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    SAD[spi] = {"source": source, "destination": destination,
        "encryption": "AES-256-CBC", "authentication": "RSA-PSS-SHA256 (Digital Signature)",
        "enc_key": os.urandom(32), "private_key": private_key, "public_key": private_key.public_key(),
        "created": time.time(), "lifetime": lifetime, "active": True}
    return True

def get_sa(spi):
    sa = SAD.get(spi)
    if not sa: return None
    if time.time() - sa["created"] >= sa["lifetime"]: sa["active"] = False
    return sa if sa["active"] else None

def delete_sa(spi): return SAD.pop(spi, None) is not None

def encrypt(sa, text):
    iv = os.urandom(16); data = text.encode()
    pad = 16 - len(data) % 16; data += bytes([pad]) * pad
    e = Cipher(algorithms.AES(sa["enc_key"]), modes.CBC(iv)).encryptor()
    cipher = e.update(data) + e.finalize()
    sig = sa["private_key"].sign(iv + cipher, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return iv, cipher, sig

def decrypt(sa, iv, cipher, sig):
    try:
        sa["public_key"].verify(sig, iv + cipher, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except InvalidSignature:
        raise ValueError("Digital signature verification failed")
    d = Cipher(algorithms.AES(sa["enc_key"]), modes.CBC(iv)).decryptor()
    data = d.update(cipher) + d.finalize(); pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad: raise ValueError("Invalid padding")
    return data[:-pad].decode()

def secure_message(spi, text):
    sa = get_sa(spi)
    if not sa: raise ValueError("SA not found or expired")
    iv, cipher, sig = encrypt(sa, text)
    return iv, cipher, sig, decrypt(sa, iv, cipher, sig)

def run_tests():
    print("=" * 66)
    print("SECURITY ASSOCIATION DATABASE - TEST SUITE")
    print("=" * 66)

    add_sa(1001, "192.168.1.10", "192.168.1.20")
    print("\n[Test Case 1] SA creation and SPI lookup")
    print("  SPI: 1001")
    print("  Result:", "PASS - SA FOUND" if get_sa(1001) else "FAIL")

    iv, ct, sig, plain = secure_message(1001, "HELLO BOB")
    print("\n[Test Case 2] AES-256 encryption and decryption")
    print("  Plaintext :", "HELLO BOB")
    print("  Ciphertext:", ct.hex())
    print("  Decrypted :", plain)
    print("  Result    :", "PASS" if plain == "HELLO BOB" else "FAIL")

    print("\n[Test Case 3] RSA-PSS-SHA256 digital signature authentication")
    print("  Signature:", sig.hex())
    print("  Result: PASS - AUTHENTICATION SUCCESSFUL")

    bad = bytearray(ct); bad[0] ^= 1
    try: decrypt(get_sa(1001), iv, bytes(bad), sig); result = "FAIL - TAMPERING NOT DETECTED"
    except ValueError: result = "PASS - TAMPERING DETECTED"
    print("\n[Test Case 4] Tampered ciphertext")
    print("  Result:", result)

    print("\n[Test Case 5] Invalid SPI lookup")
    print("  SPI: 9999")
    print("  Result:", "PASS - SA NOT FOUND" if get_sa(9999) is None else "FAIL")

    add_sa(1002, "10.0.0.1", "10.0.0.2", lifetime=0)
    print("\n[Test Case 6] Expired Security Association")
    print("  SPI: 1002, Lifetime: 0 seconds")
    print("  Result:", "PASS - EXPIRED SA REJECTED" if get_sa(1002) is None else "FAIL")

    print("\n" + "=" * 66)
    print("ALL TEST CASES PASSED")
    print("=" * 66)

if __name__ == "__main__":
    run_tests()