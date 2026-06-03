def parse_frame(frame_hex: str) -> tuple[int, int, int]:
    """解析单个加密帧，返回(N,e,c)大整数"""
    n = int(frame_hex[:256], 16)
    e = int(frame_hex[256:512], 16)
    c = int(frame_hex[512:], 16)
    return n, e, c


def extract_plaintext(m_f: int) -> tuple[int, str]:
    """
    正确提取通信序号和明文分片（严格匹配赛题填充规则）
    512比特填充结构：
    [64bit 标志位] + [32bit 通信序号] + [352bit 0] + [64bit 明文ASCII]
    """
    # 提取明文：最低64比特
    plain_bits = m_f & ((1 << 64) - 1)
    plain_bytes = plain_bits.to_bytes(8, byteorder="big")
    plaintext = plain_bytes.decode("ascii")

    # ✅ 修正：通信序号在标志位之后，即右移416位（512-64-32），取32比特
    seq_num = (m_f >> 416) & 0xFFFFFFFF
    return seq_num, plaintext


if __name__ == "__main__":
    # 你的4个文件名
    frame_files = ["Frame0.txt", "Frame1.txt", "Frame2.txt", "Frame3.txt"]
    print(f"正在读取{len(frame_files)}个Frame文件：{frame_files}")

    # 解析所有帧
    frames = []
    for f in frame_files:
        with open(f, "r", encoding="utf-8") as file:
            content = file.read().strip()
            frames.append(content)

    parsed = [parse_frame(f) for f in frames]
    Ns, es, cs = zip(*parsed)

    # 确认公钥指数e=65537
    e = es[0]
    assert all(ei == e for ei in es), "公钥指数不固定"
    print(f"\n✅ 确认公钥指数e={e} (0x{e:x})")

    # 正确的RSA参数
    p1 = 0xC60C5F1B997ED8A5E340023F33D2E269CFB423A3CF66B46D3F686747403A92B1265CB12B9A4E0135B890254F31A2C3F96A0427B39A36DEFDEEB85C57A80A9641
    q1 = 0xD684DA331AB6157DA338B6D7B08AB4C1B72C29BB7F9EF445466056DFDBF29809C4D4A2435986A40DE688AFE7CC5A5C519F7C63CB486E44D523B0E1EF21C22199
    phi1 = (p1 - 1) * (q1 - 1)
    d1 = pow(e, -1, phi1)

    p2 = 0xD502B3D96C648A9393966CDD37188D37576AA221290C861B347ED7A57640993F7ED2D16992B42AA3CA66936D3268DE47EB3A61B1495C982BF54EC0350B907C4F3CA272F9ED04EEB355367DFDA1B89357130A25411DAC4E3B8A1EECC594E0435F0E7298897B54D6C334062C8D8508AC67CEDAECD1A5FCA84BF2EE5D
    q2 = 0xE00258CB6F
    phi2 = (p2 - 1) * (q2 - 1)
    d2 = pow(e, -1, phi2)

    # 解密所有帧，自动去重
    recovered = {}
    # 解密前两个帧
    for i in range(2):
        c = cs[i]
        m_f = pow(c, d1, Ns[i])
        seq, plain = extract_plaintext(m_f)
        if seq not in recovered:
            recovered[seq] = plain
        print(f"✅ 解密帧{i}：通信序号{seq}，明文分片：{repr(plain)}")

    # 解密后两个帧
    for i in range(2, 4):
        c = cs[i]
        m_f = pow(c, d2, Ns[i])
        seq, plain = extract_plaintext(m_f)
        if seq not in recovered:
            recovered[seq] = plain
        print(f"✅ 解密帧{i}：通信序号{seq}，明文分片：{repr(plain)}")

    # 按序号排序拼接
    full_plain = "".join([recovered[seq] for seq in sorted(recovered.keys())])
    print(f"\n🎉 完整通关密语：{repr(full_plain)}")

    # 输出RSA参数
    print(f"\n✅ 第一组RSA参数（Frame0、Frame1）：")
    print(f"p={hex(p1)}")
    print(f"q={hex(q1)}")
    print(f"N={hex(Ns[0])}")
    print(f"e={hex(e)}")
    print(f"d={hex(d1)}")

    print(f"\n✅ 第二组RSA参数（Frame2、Frame3）：")
    print(f"p={hex(p2)}")
    print(f"q={hex(q2)}")
    print(f"N={hex(Ns[2])}")
    print(f"e={hex(e)}")
    print(f"d={hex(d2)}")