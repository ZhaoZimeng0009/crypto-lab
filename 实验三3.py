# challenge11_ecb_cbc_detector.py
"""Detect whether an oracle is using ECB or CBC mode."""
import os
import random
from Crypto.Cipher import AES

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def random_aes_key() -> bytes:
    return os.urandom(16)

def encryption_oracle(plaintext: bytes):
    """Randomly encrypt under ECB or CBC, prepend/append random bytes."""
    key = random_aes_key()
    prefix_len = random.randint(5, 10)
    suffix_len = random.randint(5, 10)
    plaintext = os.urandom(prefix_len) + plaintext + os.urandom(suffix_len)
    mode = random.choice(['ECB', 'CBC'])
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))
    else:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))
    return ciphertext, mode

def detect_mode(ciphertext: bytes) -> str:
    """Detect ECB by looking for repeated 16-byte blocks."""
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    if len(blocks) != len(set(blocks)):
        return "ECB"
    else:
        return "CBC"

if __name__ == "__main__":
    correct = 0
    trials = 100
    for _ in range(trials):
        pt = b'A' * 64  # enough to cause repetition in ECB
        ct, mode = encryption_oracle(pt)
        guess = detect_mode(ct)
        if guess == mode:
            correct += 1
    print(f"Detection accuracy: {correct}/{trials}")