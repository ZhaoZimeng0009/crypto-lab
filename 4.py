import base64


# ========== 1. 汉明距离函数 ==========
def hamming_distance(b1, b2):
    """计算两个字节串的汉明距离（bit 不同数）"""
    xor_result = bytes([a ^ b for a, b in zip(b1, b2)])
    return sum(bin(byte).count('1') for byte in xor_result)


# 验证汉明距离
test1 = b"this is a test"
test2 = b"wokka wokka!!!"
print(f"汉明距离测试: {hamming_distance(test1, test2)}")  # 应该输出 37


# ========== 2. 单字节 XOR 破解（英文评分） ==========
def break_single_byte_xor(byte_block):
    """对单个字节块进行单字节 XOR 破解，返回最佳密钥字节"""
    # 英文字母频率（ETAOIN SHRDLU）
    freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
        's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
        'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
        'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2,
        'q': 0.1, 'z': 0.1
    }

    def score_text(text):
        try:
            text = text.decode('ascii')
        except:
            return -999999

        text_lower = text.lower()
        letter_count = sum(1 for c in text_lower if c.isalpha())
        space_count = text_lower.count(' ')

        if len(text) == 0:
            return -999999
        letter_ratio = letter_count / len(text)
        if letter_ratio < 0.5:
            return -1000 + letter_count

        freq_score = sum(freq.get(c, 0) for c in text_lower if c.isalpha())
        space_score = (space_count / len(text)) * 200
        printable_score = sum(1 for c in text if 32 <= ord(c) <= 126) * 2

        return freq_score + space_score + printable_score

    best_score = -999999
    best_key = 0
    for key in range(256):
        decrypted = bytes([b ^ key for b in byte_block])
        score = score_text(decrypted)
        if score > best_score:
            best_score = score
            best_key = key

    return best_key


# ========== 3. 主破解函数 ==========
def break_repeating_key_xor(ciphertext_bytes):
    # 步骤 1-4: 猜测密钥长度
    key_sizes = []
    for KEYSIZE in range(2, 41):
        # 取前 4 个 KEYSIZE 块
        blocks = [ciphertext_bytes[i * KEYSIZE:(i + 1) * KEYSIZE] for i in range(4)]
        if len(blocks) < 2:
            continue

        distances = []
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                if len(blocks[i]) == KEYSIZE and len(blocks[j]) == KEYSIZE:
                    dist = hamming_distance(blocks[i], blocks[j]) / KEYSIZE
                    distances.append(dist)

        avg_distance = sum(distances) / len(distances)
        key_sizes.append((avg_distance, KEYSIZE))

    # 取最小的 3 个
    key_sizes.sort()
    candidates = [KEYSIZE for _, KEYSIZE in key_sizes[:3]]
    print(f"候选密钥长度: {candidates}")

    # 步骤 5-8: 对每个候选密钥长度尝试破解
    best_plaintext = None
    best_score = -999999
    best_key = None

    for KEYSIZE in candidates:
        # 步骤 5: 分成 KEYSIZE 长度的块
        blocks = [ciphertext_bytes[i::KEYSIZE] for i in range(KEYSIZE)]

        # 步骤 6-7: 对每个转置块进行单字节 XOR 破解
        key_bytes = []
        for block in blocks:
            key_byte = break_single_byte_xor(block)
            key_bytes.append(key_byte)

        key = bytes(key_bytes)

        # 解密
        plaintext = bytes([ciphertext_bytes[i] ^ key[i % KEYSIZE] for i in range(len(ciphertext_bytes))])

        # 评分英文程度
        try:
            text = plaintext.decode('ascii')
            letter_ratio = sum(1 for c in text if c.isalpha()) / len(text)
            space_ratio = text.count(' ') / len(text)
            score = letter_ratio * 1000 + space_ratio * 500
            if score > best_score:
                best_score = score
                best_plaintext = plaintext
                best_key = key
        except:
            pass

    return best_key, best_plaintext


# ========== 主程序 ==========
if __name__ == "__main__":
    # 读取 base64 文件
    with open("6.txt", "r") as f:
        base64_data = "".join(line.strip() for line in f)

    ciphertext = base64.b64decode(base64_data)

    print("正在破解重复密钥 XOR...")
    key, plaintext = break_repeating_key_xor(ciphertext)

    print(f"\n密钥: {key.decode('ascii')}")
    print(f"\n明文:\n{plaintext.decode('ascii')[:500]}...")