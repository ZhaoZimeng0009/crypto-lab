from Crypto.Cipher import AES
import base64
import os

# ========== 模拟加密神谕 ==========
RANDOM_KEY = os.urandom(16)

UNKNOWN_B64 = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)

UNKNOWN_STRING = base64.b64decode(UNKNOWN_B64)


def encryption_oracle(your_string: bytes) -> bytes:
    """加密神谕：AES-128-ECB(your_string || unknown_string, random_key)"""
    cipher = AES.new(RANDOM_KEY, AES.MODE_ECB)
    plaintext = your_string + UNKNOWN_STRING
    # PKCS#7 填充
    padding_len = AES.block_size - (len(plaintext) % AES.block_size)
    padded_plaintext = plaintext + bytes([padding_len] * padding_len)
    return cipher.encrypt(padded_plaintext)


# ========== 攻击代码 ==========
def detect_block_size(oracle) -> int:
    """检测 ECB 加密的块大小"""
    prev_len = len(oracle(b''))
    for i in range(1, 64):
        ct = oracle(b'A' * i)
        curr_len = len(ct)
        if curr_len != prev_len:
            return curr_len - prev_len
        prev_len = curr_len
    raise Exception("无法检测块大小")


def detect_ecb(oracle, block_size: int) -> bool:
    """检测是否使用 ECB 模式"""
    pt = b'A' * (block_size * 3)
    ct = oracle(pt)
    blocks = [ct[i * block_size:(i + 1) * block_size] for i in range(len(ct) // block_size)]
    return len(set(blocks)) < len(blocks)


def get_unknown_length(oracle, block_size: int) -> int:
    """
    准确获取 unknown_string 的长度
    原理：不断增加输入长度，直到密文长度增加
    """
    base_len = len(oracle(b''))
    for i in range(1, block_size * 2):
        current_len = len(oracle(b'A' * i))
        if current_len > base_len:
            # 触发了新的块
            # unknown_len = (base_len - block_size) + (block_size - i)
            unknown_len = base_len - block_size + (block_size - i)
            return unknown_len
    return base_len - block_size  # 如果 unknown_string 刚好是块大小的整数倍


def byte_at_a_time_decrypt(oracle, block_size: int) -> bytes:
    """
    逐字节解密未知字符串（正确处理所有情况）
    """
    # 获取未知字符串的准确长度
    unknown_len = get_unknown_length(oracle, block_size)
    print(f"[*] 目标未知字符串长度: {unknown_len} 字节")

    unknown = b''

    # 逐字节解密
    for pos in range(unknown_len):
        # 计算需要多少填充字节，让未知字节成为块的最后一个字节
        # 这里的 pos 是 unknown_string 中的位置（0-based）
        pad_len = (block_size - 1 - (pos % block_size))
        test_input = b'A' * pad_len

        # 获取目标密文（解密第 pos 个字节）
        ct = oracle(test_input)
        block_idx = pos // block_size
        target_block = ct[block_idx * block_size:(block_idx + 1) * block_size]

        # 构造字典并查找匹配
        found = None
        for guess in range(256):
            # 构造测试明文：填充 + 已知部分 + 猜测字节
            guess_input = test_input + unknown + bytes([guess])
            guess_ct = oracle(guess_input)
            guess_block = guess_ct[block_idx * block_size:(block_idx + 1) * block_size]

            if guess_block == target_block:
                found = bytes([guess])
                break

        if found is None:
            print(f"[!] 警告：无法解密第 {pos} 个字节")
            break

        unknown += found

        # 进度显示
        if (pos + 1) % 16 == 0 or pos == unknown_len - 1:
            print(f"[*] 已解密 {pos + 1}/{unknown_len} 字节")

    return unknown


def main():
    print("开始攻击...")

    # 1. 检测块大小
    block_size = detect_block_size(encryption_oracle)
    print(f"[+] 检测到块大小: {block_size} 字节")

    # 2. 检测 ECB 模式
    if detect_ecb(encryption_oracle, block_size):
        print("[+] 确认使用 ECB 模式")
    else:
        print("[-] 警告：可能不是 ECB 模式")
        return

    # 3. 解密未知字符串
    print("\n[*] 开始逐字节解密...")
    decrypted = byte_at_a_time_decrypt(encryption_oracle, block_size)

    # 4. 输出结果
    print("\n" + "=" * 50)
    print("解密结果：")
    print("=" * 50)
    try:
        print(decrypted.decode('utf-8'))
    except UnicodeDecodeError:
        print(decrypted)

    # 5. 验证
    print("\n" + "=" * 50)
    print("验证信息：")
    print("=" * 50)
    print(f"解密长度: {len(decrypted)} 字节")
    print(f"原始长度: {len(UNKNOWN_STRING)} 字节")
    print(f"解密结果匹配原始数据: {decrypted == UNKNOWN_STRING}")

    if decrypted == UNKNOWN_STRING:
        print("\n 攻击成功！成功解密了未知字符串！")
    else:
        print("\n 解密不完全，请检查代码逻辑")


if __name__ == "__main__":
    main()