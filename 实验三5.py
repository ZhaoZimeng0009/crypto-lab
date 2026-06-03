import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def parse_kv(s):
    d = {}
    for pair in s.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            d[k] = v
    return d

def encode_profile(profile_dict):
    return '&'.join(f"{k}={v}" for k, v in profile_dict.items())

def profile_for(email):
    sanitized = email.replace('&', '').replace('=', '')
    profile = {
        'email': sanitized,
        'uid': 10,
        'role': 'user'
    }
    return encode_profile(profile)

KEY = os.urandom(16)

def encrypt_profile(encoded_profile):
    cipher = AES.new(KEY, AES.MODE_ECB)
    padded = pad(encoded_profile.encode(), 16)
    return cipher.encrypt(padded)

def decrypt_and_parse(ciphertext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), 16)
    return parse_kv(decrypted.decode())

email1 = 'A' * 13
cipher1 = encrypt_profile(profile_for(email1))

email2 = 'A' * 10 + 'admin' + chr(11) * 11
cipher2 = encrypt_profile(profile_for(email2))

malicious_cipher = cipher1[:-16] + cipher2[16:32]

result = decrypt_and_parse(malicious_cipher)
print(result)