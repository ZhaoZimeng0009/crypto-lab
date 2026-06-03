from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(16)
IV = get_random_bytes(16)


def pad(s, block_size=16):
    padding_len = block_size - (len(s) % block_size)
    return s + bytes([padding_len] * padding_len)


def unpad(s):
    padding_len = s[-1]
    for i in range(1, padding_len + 1):
        if s[-i] != padding_len:
            raise ValueError("Invalid padding")
    return s[:-padding_len]


def quote(s):
    return s.replace(b';', b'";"').replace(b'=', b'"="')


def encryption_oracle(user_input):
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    quoted_input = quote(user_input)
    plaintext = prefix + quoted_input + suffix

    padded = pad(plaintext)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(padded)

    return ciphertext, IV


def decryption_oracle(ciphertext, iv):
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    try:
        plaintext = unpad(decrypted)
    except ValueError:
        return False

    return b";admin=true;" in plaintext


def bitflipping_attack():
    target = b";admin=true;"

    input_data = b"A" * 16
    ciphertext, iv = encryption_oracle(input_data)

    modified = bytearray(ciphertext)

    for i in range(len(target)):
        pos_in_prev_block = 16 + i
        original_char = ord('A')
        desired_char = target[i]

        modified[pos_in_prev_block] ^= original_char ^ desired_char

    return decryption_oracle(bytes(modified), iv)


if __name__ == "__main__":
    print(bitflipping_attack())