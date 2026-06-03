import math


def calculate_rsa_e_sum():
    p = 1009
    q = 3643
    phi = (p - 1) * (q - 1)
    p_minus_1 = p - 1
    q_minus_1 = q - 1

    min_unconcealed = float('inf')
    total_sum = 0
    e_count = 0

    # 优化：仅遍历奇数e（phi为偶数，gcd(e,phi)=1必为奇数）
    for e in range(3, phi, 2):
        if math.gcd(e, phi) != 1:
            continue
        k = e - 1
        g1 = math.gcd(k, p_minus_1)
        g2 = math.gcd(k, q_minus_1)
        current = (1 + g1) * (1 + g2)

        if current < min_unconcealed:
            min_unconcealed = current
            total_sum = e
            e_count = 1
        elif current == min_unconcealed:
            total_sum += e
            e_count += 1

    return min_unconcealed, e_count, total_sum


# 执行计算
min_num, count, sum_e = calculate_rsa_e_sum()
print(f"最小未加密消息数: {min_num}")
print(f"满足条件的e的个数: {count}")
print(f"所有满足条件的e的和: {sum_e}")