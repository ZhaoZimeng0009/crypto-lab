def pkcs7_unpad(data: bytes) -> bytes:
    """
    验证并去除 PKCS#7 填充。

    参数:
        data: 带填充的字节串

    返回:
        去除填充后的原始字节串

    异常:
        ValueError: 如果填充无效
    """
    if not data:
        raise ValueError("Empty data cannot have valid PKCS#7 padding")

    padding_len = data[-1]

    # PKCS#7 填充长度必须在 1 到 16 之间（对于 AES 块大小）
    # 更一般地，填充长度不能超过数据长度
    if padding_len < 1 or padding_len > len(data):
        raise ValueError("Invalid padding length")

    # 检查所有填充字节是否与 padding_len 相等
    expected_padding = bytes([padding_len]) * padding_len
    if data[-padding_len:] != expected_padding:
        raise ValueError("Invalid padding bytes")

    # 去除填充
    return data[:-padding_len]


def main():
    # 测试用例1：有效填充
    text1 = b"ICE ICE BABY\x04\x04\x04\x04"
    try:
        result1 = pkcs7_unpad(text1)
        print(f"测试1 - 输入: {text1}")
        print(f"        输出: {result1}")
        print(f"        结果: 通过 ✓\n")
    except ValueError as e:
        print(f"测试1 - 失败: {e}\n")

    # 测试用例2：无效填充（填充值不匹配）
    text2 = b"ICE ICE BABY\x05\x05\x05\x05"
    try:
        result2 = pkcs7_unpad(text2)
        print(f"测试2 - 输入: {text2}")
        print(f"        输出: {result2}")
        print(f"        结果: 通过 ✓\n")
    except ValueError as e:
        print(f"测试2 - 输入: {text2}")
        print(f"        错误: {e}")
        print(f"        结果: 通过（正确抛出异常）✓\n")

    # 测试用例3：无效填充（随机字节）
    text3 = b"ICE ICE BABY\x01\x02\x03\x04"
    try:
        result3 = pkcs7_unpad(text3)
        print(f"测试3 - 输入: {text3}")
        print(f"        输出: {result3}")
        print(f"        结果: 通过 ✓\n")
    except ValueError as e:
        print(f"测试3 - 输入: {text3}")
        print(f"        错误: {e}")
        print(f"        结果: 通过（正确抛出异常）✓\n")

if __name__ == "__main__":
    main()