from typing import List, Union
import base64


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """对两个字节串进行 XOR 运算"""
    return bytes(x ^ y for x, y in zip(a, b))


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128 ECB 加密（单个块）"""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128 ECB 解密（单个块）"""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    CBC 模式加密

    参数:
        plaintext: 明文（长度必须是16的倍数，需要预先填充）
        key: AES-128 密钥（16字节）
        iv: 初始化向量（16字节）

    返回:
        密文
    """
    block_size = 16
    ciphertext = b''
    previous_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # XOR 与前一个密文块（或 IV）
        xored = xor_bytes(block, previous_block)
        # ECB 加密
        encrypted_block = aes_ecb_encrypt(xored, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    CBC 模式解密

    参数:
        ciphertext: 密文（长度必须是16的倍数）
        key: AES-128 密钥（16字节）
        iv: 初始化向量（16字节）

    返回:
        明文
    """
    block_size = 16
    plaintext = b''
    previous_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        # ECB 解密
        decrypted = aes_ecb_decrypt(block, key)
        # XOR 与前一个密文块（或 IV）
        plain_block = xor_bytes(decrypted, previous_block)
        plaintext += plain_block
        previous_block = block

    return plaintext


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 填充"""
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """去除 PKCS#7 填充"""
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("无效的填充")
    if not all(b == padding_len for b in data[-padding_len:]):
        raise ValueError("无效的填充")
    return data[:-padding_len]


# 测试数据
def test_cbc():
    """测试 CBC 模式"""
    key = b"YELLOW SUBMARINE"  # 16字节
    iv = b"\x00" * 16

    # 题目中的文件内容（需要先解密）
    # 这里我先加密一些测试数据，再解密验证
    test_plaintext = b"This is a test message for CBC mode implementation!"
    padded_plaintext = pkcs7_pad(test_plaintext)

    print("原始明文:", test_plaintext)
    print("填充后:", padded_plaintext.hex())

    # 加密
    ciphertext = cbc_encrypt(padded_plaintext, key, iv)
    print("密文:", ciphertext.hex())

    # 解密
    decrypted_padded = cbc_decrypt(ciphertext, key, iv)
    decrypted = pkcs7_unpad(decrypted_padded)
    print("解密后:", decrypted)

    assert decrypted == test_plaintext
    print("\n测试通过！")


def decrypt_file(encrypted_data: bytes, key: bytes, iv: bytes) -> str:

    decrypted_padded = cbc_decrypt(encrypted_data, key, iv)
    decrypted = pkcs7_unpad(decrypted_padded)
    return decrypted.decode('utf-8', errors='replace')


if __name__ == "__main__":
    test_cbc()