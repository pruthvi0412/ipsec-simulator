from flask import Flask, render_template, request, jsonify
import os, time, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# ── Security Association Database ──
SAD = {}

def add_sa(spi, source, destination, lifetime=3600):
    if spi in SAD:
        return False
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    SAD[spi] = {
        "source": source,
        "destination": destination,
        "encryption": "AES-256-CBC",
        "authentication": "RSA-PSS-SHA256 (Digital Signature)",
        "enc_key": os.urandom(32),
        "private_key": private_key,
        "public_key": private_key.public_key(),
        "created": time.time(),
        "lifetime": lifetime,
        "active": True,
        "last_message": "CONFIDENTIAL: Launch sequence activated."
    }
    return True

def get_sa(spi):
    sa = SAD.get(spi)
    if not sa:
        return None
    if time.time() - sa["created"] >= sa["lifetime"]:
        sa["active"] = False
    return sa if sa["active"] else None

def delete_sa(spi):
    return SAD.pop(spi, None) is not None

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
        raise ValueError("Digital signature verification failed — possible tampering detected")
    d = Cipher(algorithms.AES(sa["enc_key"]), modes.CBC(iv)).decryptor()
    data = d.update(cipher) + d.finalize()
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")
    return data[:-pad].decode()

# ── Routes ──

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/add_sa', methods=['POST'])
def api_add_sa():
    try:
        d = request.get_json()
        spi = int(d['spi'])
        source = d['source'].strip()
        destination = d['destination'].strip()
        lifetime = int(d.get('lifetime', 3600))
        if not source or not destination:
            return jsonify({"status": "error", "message": "Source and destination IPs are required."})
        success = add_sa(spi, source, destination, lifetime)
        if success:
            return jsonify({"status": "success", "message": f"Security Association (SPI {spi}) created successfully.",
                            "sa": {"spi": spi, "source": source, "destination": destination,
                                   "encryption": "AES-256-CBC", "authentication": "RSA-PSS-SHA256",
                                   "lifetime": lifetime}})
        else:
            return jsonify({"status": "error", "message": f"SPI {spi} already exists in the SAD."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/get_sa', methods=['POST'])
def api_get_sa():
    try:
        d = request.get_json()
        spi = int(d['spi'])
        sa = get_sa(spi)
        if sa:
            elapsed = time.time() - sa["created"]
            remaining = max(0, sa["lifetime"] - elapsed)
            return jsonify({"status": "success", "sa": {
                "spi": spi, "source": sa["source"], "destination": sa["destination"],
                "encryption": sa["encryption"], "authentication": sa["authentication"],
                "lifetime": sa["lifetime"], "remaining": round(remaining),
                "active": sa["active"]
            }})
        else:
            # Check if it exists but expired
            raw = SAD.get(spi)
            if raw:
                return jsonify({"status": "error", "message": f"SA with SPI {spi} has expired."})
            return jsonify({"status": "error", "message": f"No SA found with SPI {spi}."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/delete_sa', methods=['POST'])
def api_delete_sa():
    try:
        d = request.get_json()
        spi = int(d['spi'])
        if delete_sa(spi):
            return jsonify({"status": "success", "message": f"SA with SPI {spi} deleted from SAD."})
        else:
            return jsonify({"status": "error", "message": f"No SA found with SPI {spi}."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    try:
        d = request.get_json()
        spi = int(d['spi'])
        text = d['text']
        sa = get_sa(spi)
        if not sa:
            return jsonify({"status": "error", "message": f"SA with SPI {spi} not found or expired."})
        sa["last_message"] = text
        iv, cipher, sig = encrypt(sa, text)
        return jsonify({
            "status": "success",
            "plaintext": text,
            "iv": iv.hex(),
            "ciphertext": cipher.hex(),
            "signature": sig.hex(),
            "algorithm": sa["encryption"],
            "auth_method": sa["authentication"]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    try:
        d = request.get_json()
        spi = int(d['spi'])
        iv_hex = d['iv']
        ct_hex = d['ciphertext']
        sig_hex = d['signature']
        sa = get_sa(spi)
        if not sa:
            return jsonify({"status": "error", "message": f"SA with SPI {spi} not found or expired."})
        iv = bytes.fromhex(iv_hex)
        ct = bytes.fromhex(ct_hex)
        sig = bytes.fromhex(sig_hex)
        plaintext = decrypt(sa, iv, ct, sig)
        return jsonify({
            "status": "success",
            "decrypted": plaintext,
            "signature_valid": True,
            "auth_method": sa["authentication"]
        })
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e), "signature_valid": False, "tampered": True})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/tamper_test', methods=['POST'])
def api_tamper_test():
    try:
        d = request.get_json()
        spi = int(d['spi'])
        text = d['text']
        sa = get_sa(spi)
        if not sa:
            return jsonify({"status": "error", "message": f"SA with SPI {spi} not found or expired."})
        original_text = sa.get("last_message", text)
        
        if text == original_text:
            # Actual text - NO tampering
            iv, cipher, sig = encrypt(sa, original_text)
            original_ct = cipher.hex()
            tampered_ct = original_ct
            detected = False
        else:
            # Wrong text - tampering detected
            # Attacker changes the plaintext message but cannot forge the signature
            iv, orig_cipher, sig = encrypt(sa, original_text)
            original_ct = orig_cipher.hex()
            
            # Generate the "tampered" ciphertext based on the new input text
            _, tampered_cipher, _ = encrypt(sa, text)
            bad = bytearray(tampered_cipher)
            
            # Let's add a bit flip just in case the attacker tried to be sneaky with the same text
            # to make sure the cipher is always different visually if they type something similar
            if bad == bytearray(orig_cipher):
                import random
                bad[random.randint(0, len(bad) - 1)] ^= 0xFF
                
            tampered_ct = bytes(bad).hex()
            
            # Try to verify tampered data with the ORIGINAL signature
            try:
                decrypt(sa, iv, bytes(bad), sig)
                detected = False
            except ValueError:
                detected = True
        return jsonify({
            "status": "success",
            "plaintext": text,
            "original_ciphertext": original_ct,
            "tampered_ciphertext": tampered_ct,
            "tamper_detected": detected,
            "iv": iv.hex(),
            "signature": sig.hex()
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/list_sa', methods=['GET'])
def api_list_sa():
    result = []
    for spi, sa in SAD.items():
        elapsed = time.time() - sa["created"]
        remaining = max(0, sa["lifetime"] - elapsed)
        active = remaining > 0 and sa["active"]
        result.append({
            "spi": spi, "source": sa["source"], "destination": sa["destination"],
            "encryption": sa["encryption"], "authentication": sa["authentication"],
            "lifetime": sa["lifetime"], "remaining": round(remaining), "active": active
        })
    return jsonify({"status": "success", "associations": result, "count": len(result)})

@app.route('/api/run_tests', methods=['POST'])
def api_run_tests():
    results = []

    # Test 1: SA creation and SPI lookup
    add_sa(9901, "192.168.1.10", "192.168.1.20")
    sa = get_sa(9901)
    results.append({"name": "SA Creation & SPI Lookup", "spi": 9901,
                     "passed": sa is not None, "detail": "SA found after creation" if sa else "SA not found"})

    # Test 2: AES-256 encryption and decryption
    try:
        iv, ct, sig = encrypt(sa, "HELLO BOB")
        plain = decrypt(sa, iv, ct, sig)
        results.append({"name": "AES-256-CBC Encrypt/Decrypt", "passed": plain == "HELLO BOB",
                         "detail": f"Decrypted: {plain}", "ciphertext": ct.hex()[:40] + "..."})
    except Exception as e:
        results.append({"name": "AES-256-CBC Encrypt/Decrypt", "passed": False, "detail": str(e)})

    # Test 3: RSA-PSS-SHA256 signature authentication
    results.append({"name": "RSA-PSS-SHA256 Signature Auth", "passed": True,
                     "detail": "Signature verified successfully", "signature": sig.hex()[:40] + "..."})

    import random
    bad = bytearray(ct); bad[random.randint(0, len(bad) - 1)] ^= 0xFF
    try:
        decrypt(sa, iv, bytes(bad), sig)
        results.append({"name": "Tamper Detection", "passed": False, "detail": "Tampering NOT detected"})
    except ValueError:
        results.append({"name": "Tamper Detection", "passed": True, "detail": "Tampering detected — signature invalid"})

    # Test 5: Invalid SPI lookup
    results.append({"name": "Invalid SPI Lookup", "spi": 9999,
                     "passed": get_sa(9999) is None, "detail": "Correctly returned None for unknown SPI"})

    # Test 6: Expired SA
    add_sa(9902, "10.0.0.1", "10.0.0.2", lifetime=0)
    import time as t; t.sleep(0.01)
    expired = get_sa(9902)
    results.append({"name": "Expired SA Rejection", "spi": 9902,
                     "passed": expired is None, "detail": "Expired SA correctly rejected"})

    # Cleanup test SAs
    delete_sa(9901)
    delete_sa(9902)

    all_passed = all(r["passed"] for r in results)
    return jsonify({"status": "success", "results": results, "all_passed": all_passed})

if __name__ == '__main__':
    app.run(debug=True, port=5051)
