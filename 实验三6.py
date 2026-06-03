
from Crypto.Cipher import AES

# ------------------- 辅助函数 -------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """逐字节异或两个等长字节串"""
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 填充"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """去除 PKCS#7 填充"""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("无效填充")
    return data[:-pad_len]

# ------------------- AES-128-ECB 核心 -------------------
def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-ECB 加密单个块（16字节）"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128-ECB 解密单个块"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# ------------------- CBC 模式 -------------------
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    CBC 模式加密
    plaintext: 任意明文（自动 PKCS#7 填充）
    key: 16 字节密钥
    iv: 16 字节初始化向量
    返回密文（不含 IV，IV 需要另行传输）
    """
    block_size = 16
    plaintext = pkcs7_pad(plaintext, block_size)
    ciphertext = b''
    prev = iv
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        xored = xor_bytes(block, prev)
        encrypted = aes_ecb_encrypt(xored, key)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext

def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    CBC 模式解密
    ciphertext: 密文（长度必须是块大小的整数倍）
    key: 16 字节密钥
    iv: 16 字节初始化向量
    返回去除填充后的明文
    """
    block_size = 16
    if len(ciphertext) % block_size != 0:
        raise ValueError("密文长度不是块大小的整数倍")
    plaintext = b''
    prev = iv
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypted = aes_ecb_decrypt(block, key)
        plaintext += xor_bytes(decrypted, prev)
        prev = block
    return pkcs7_unpad(plaintext)

# ------------------- 测试与解密指定文件 -------------------
if __name__ == "__main__":
    KEY = b"YELLOW SUBMARINE"   # 16 字节密钥
    IV = bytes(16)              # 全零 IV

    # 验证加解密一致性
    test_msg = b"CBC mode is awesome!"
    encrypted = cbc_encrypt(test_msg, KEY, IV)
    decrypted = cbc_decrypt(encrypted, KEY, IV)
    assert decrypted == test_msg
    print("[√] 加解密通过")
