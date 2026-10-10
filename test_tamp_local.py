import os, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sa = {
    "enc_key": os.urandom(32),
    "private_key": private_key,
    "public_key": private_key.public_key(),
}

def encrypt(sa, text):
    iv = os.urandom(16)
    data = text.encode()
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    e = Cipher(algorithms.AES(sa["enc_key"]), modes.CBC(iv)).encryptor()
    cipher = e.update(data) + e.finalize()
    sig = sa["private_key"].sign(
        iv + cipher,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return iv, cipher, sig

def decrypt(sa, iv, cipher, sig):
    try:
        sa["public_key"].verify(
            sig, iv + cipher,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise ValueError("Digital signature verification failed")
    d = Cipher(algorithms.AES(sa["enc_key"]), modes.CBC(iv)).decryptor()
    data = d.update(cipher) + d.finalize()
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")
    return data[:-pad].decode()

iv, cipher, sig = encrypt(sa, "A")
bad = bytearray(cipher)
bad[0] ^= 0xFF
try:
    decrypt(sa, iv, bytes(bad), sig)
except Exception as e:
    print("Caught:", type(e), e)

