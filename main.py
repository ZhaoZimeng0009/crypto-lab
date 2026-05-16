
import time
import itertools
import hashlib

target = '67ae1a64661ac8b4494666f58c4822408dd0a3e4'
keyChars = [('Q', 'q'), ('W', 'w'), ('%', '5'), ('(', '8'), ('=', '0'), ('I', 'i'), ('*', '+'), ('N', 'n')]


def check_mask(s):
    return s[:3].count('0') > 0 and s[3:].count('0') > 0


if __name__ == "__main__":
    stime = time.perf_counter()

    for i in range(256):
        mask = str(bin(i))[2:].zfill(8)
        if not check_mask(mask):
            continue

        C = [keyChars[j][int(mask[j])] for j in range(8)]
        for perm in itertools.permutations(C, 8):
            password = ''.join(perm)
            if hashlib.sha1(password.encode()).hexdigest() == target:
                print('The key is:', password)
                print('Timer:', round(time.perf_counter() - stime, 2), 's')
                break
        else:
            continue
        break