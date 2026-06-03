def egcd(a, b):
    """扩展欧几里得算法: ax + by = gcd(a,b)，返回(g, x, y)"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def invmod(a, mod):
    """求a在模mod下的乘法逆元，不存在则抛异常"""
    g, x, _ = egcd(a, mod)
    if g != 1:
        raise Exception(f'模逆元不存在！gcd({a},{mod})={g}≠1，请更换p/q或e')
    else:
        return x % mod


class RSA:
    def __init__(self, p, q, e=3):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.e = e

        # RSA核心条件前置检查
        if egcd(self.e, self.phi)[0] != 1:
            raise Exception(f'公钥e={e}与φ={self.phi}不互质！\n请更换p/q（推荐）或更换e')

        self.d = invmod(self.e, self.phi)
        self.pub_key = (self.e, self.n)  # 公钥 (e,n)
        self.pri_key = (self.d, self.n)  # 私钥 (d,n)
        print(f"当前RSA最大支持明文数字: {self.n - 1}")

    def encrypt_num(self, m):
        """数字明文加密 m -> c"""
        if m >= self.n or m < 0:
            raise ValueError(f"明文数字{m}超出范围！必须满足 0 ≤ m < {self.n}")
        e, n = self.pub_key
        return pow(m, e, n)

    def decrypt_num(self, c):
        """密文解密 c -> m"""
        d, n = self.pri_key
        return pow(c, d, n)

    def encrypt_str(self, plaintext: str):
        """字符串加密：str→十六进制数字→RSA加密"""
        hex_str = plaintext.encode('utf-8').hex()
        m = int(hex_str, 16)
        return self.encrypt_num(m)

    def decrypt_str(self, cipher_num):
        """数字密文解密：数字→十六进制→原字符串"""
        m = self.decrypt_num(cipher_num)
        hex_str = hex(m)[2:]  # 去掉0x前缀
        # 修复：奇数长度十六进制补前导0
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str).decode('utf-8')


# ========== 测试1：小素数测试（p=59,q=71,e=3） ==========
if __name__ == "__main__":
    # 验证题目给出的invmod示例
    print("题目invmod示例验证：invmod(17,3120) =", invmod(17, 3120))
    print("-" * 60)

    print("===== 小素数RSA测试(p=59,q=71,e=3) =====")
    p_small = 59
    q_small = 71
    rsa_small = RSA(p_small, q_small, e=3)
    print(f"公钥(e,n): {rsa_small.pub_key}")
    print(f"私钥(d,n): {rsa_small.pri_key}")

    # 数字测试（正常）
    m_test = 42
    c = rsa_small.encrypt_num(m_test)
    m_dec = rsa_small.decrypt_num(c)
    print(f"数字测试：明文={m_test}, 密文={c}, 解密还原={m_dec}")

    # 短字符串测试（长度≤2个字符，确保数字<4189）
    short_text = "Hi"
    c_short = rsa_small.encrypt_str(short_text)
    dec_short = rsa_small.decrypt_str(c_short)
    print(f"短字符串测试：明文={short_text}, 密文={c_short}, 解密还原={dec_short}\n")

    # ========== 测试2：大素数测试（支持长字符串） ==========
    print("===== 大素数RSA测试(p=1009,q=3643,e=3) =====")
    p_big = 1009
    q_big = 3643
    rsa_big = RSA(p_big, q_big, e=3)
    print(f"公钥(e,n): {rsa_big.pub_key}")
    print(f"私钥(d,n): {rsa_big.pri_key}")

    # 长字符串测试（"Hello RSA!" 完全没问题）
    long_text = "Hello RSA!"
    c_long = rsa_big.encrypt_str(long_text)
    dec_long = rsa_big.decrypt_str(c_long)
    print(f"长字符串测试：明文={long_text}")
    print(f"加密后密文: {c_long}")
    print(f"解密还原: {dec_long}")