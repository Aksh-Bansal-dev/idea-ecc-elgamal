def addInv(A):
    return 16-A

def modInv(A):
    M = 17 
    g = gcd(A, M)
 
    if (g != 1):
        # print("Inverse doesn't exist",A)
        return 0
 
    else:
 
        # If A and M are relatively prime,
        # then modulo inverse is A^(M-2) mod M
        return power(A, M - 2, M)
 
# To compute x^y under modulo M
def power(x, y, M):
 
    if (y == 0):
        return 1
 
    p = power(x, y // 2, M) % M
    p = (p * p) % M
 
    if(y % 2 == 0):
        return p
    else:
        return ((x * p) % M)
 
# Function to return gcd of a and b
def gcd(a, b):
    if (a == 0):
        return b
 
    return gcd(b % a, a)
 
def _mul(x, y):
    assert 0 <= x <= 15
    assert 0 <= y <= 15

    if x == 0:
        x = 16
    if y == 0:
        y = 16

    r = (x * y) % 17

    if r == 16:
        r = 0

    assert 0 <= r <= 15
    return r


def _KA_layer(x1, x2, x3, x4, round_keys):
    assert 0 <= x1 <= 15
    assert 0 <= x2 <= 15
    assert 0 <= x3 <= 15
    assert 0 <= x4 <= 15
    z1, z2, z3, z4 = round_keys[0:4]
    assert 0 <= z1 <= 15
    assert 0 <= z2 <= 15
    assert 0 <= z3 <= 15
    assert 0 <= z4 <= 15

    y1 = _mul(x1, z1)
    y2 = (x2 + z2) % 16
    y3 = (x3 + z3) % 16
    y4 = _mul(x4, z4)

    return y1, y2, y3, y4


def _MA_layer(y1, y2, y3, y4, round_keys):
    assert 0 <= y1 <= 16
    assert 0 <= y2 <= 16
    assert 0 <= y3 <= 16
    assert 0 <= y4 <= 16
    z5, z6 = round_keys[4:6]
    assert 0 <= z5 <= 16
    assert 0 <= z6 <= 16

    p = y1 ^ y3
    q = y2 ^ y4

    s = _mul(p, z5)
    t = _mul((q + s) % 16, z6)
    u = (s + t) % 16

    x1 = y1 ^ t
    x2 = y2 ^ u
    x3 = y3 ^ t
    x4 = y4 ^ u

    return x1, x2, x3, x4


class IDEA:
    def __init__(self, key):
        self._keys = None
        self.change_key(key)

    def change_key(self, key):
        assert 0 <= key < (1 << 128)
        modulus = 1 << 32

        sub_keys = []
        for i in range(5 * 6):
            sub_keys.append((key >> (28 - 4 * (i % 8))) % 16)
            # print(bin((key >> (28 - 4 * (i % 8))) % 16))
            # print((key >> (28 - 4 * (i % 8))) % 16)
            if i % 8 == 7:
                key = ((key << 6) | (key >> 26)) % modulus

        keys = []
        for i in range(5):
            round_keys = sub_keys[6 * i: 6 * (i + 1)]
            keys.append(tuple(round_keys))

        ikeys = []
        for i in range(4):
            round_keys = [-1 for xxx in range(6)]

            round_keys[0] = modInv(sub_keys[6*(4-i)+0])
            round_keys[1] = addInv(sub_keys[6*(4-i)+1])
            round_keys[2] = addInv(sub_keys[6*(4-i)+2])
            round_keys[3] = modInv(sub_keys[6*(4-i)+3])
            round_keys[4] = sub_keys[6*(3-i)+4]
            round_keys[5] = sub_keys[6*(3-i)+5]

            ikeys.append(tuple(round_keys))
            
        round_keys = [-1 for xxx in range(6)]
        round_keys[0] = modInv(sub_keys[0])
        round_keys[1] = addInv(sub_keys[1])
        round_keys[2] = addInv(sub_keys[2])
        round_keys[3] = modInv(sub_keys[3])
        ikeys.append(tuple(round_keys))

        # for i in range(len(ikeys)):
        #     for j in range(len(ikeys[0])):
        #         print(bin(ikeys[i][j]))

        self._keys = tuple(keys)
        self._ikeys = tuple(ikeys)

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << 64)
        x1 = (ciphertext >> 12) & 15
        x2 = (ciphertext >> 8) & 15
        x3 = (ciphertext >> 4) & 15
        x4 = ciphertext & 15

        for i in range(4):
            round_keys = self._ikeys[i]

            y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

            # x2, x3 = x3, x2

        # Note: The words x2 and x3 are not permuted in the last round
        # So here we use x1, x3, x2, x4 as input instead of x1, x2, x3, x4
        # in order to cancel the last permutation x2, x3 = x3, x2
        y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, self._ikeys[4])

        plaintext = (y1 << 12) | (y2 << 8) | (y3 << 4) | y4
        return plaintext

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << 64)
        x1 = (plaintext >> 12) & 15
        x2 = (plaintext >> 8) & 15
        x3 = (plaintext >> 4) & 15
        x4 = plaintext & 15

        for i in range(4):
            round_keys = self._keys[i]

            y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
            x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)

            # x2, x3 = x3, x2

        # Note: The words x2 and x3 are not permuted in the last round
        # So here we use x1, x3, x2, x4 as input instead of x1, x2, x3, x4
        # in order to cancel the last permutation x2, x3 = x3, x2
        # y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, self._keys[4])
        y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, self._keys[4])

        ciphertext = (y1 << 12) | (y2 << 8) | (y3 << 4) | y4
        return ciphertext


def main():
    plain = int("1001110010101100",2)
    # plain = 1000
    key = int("11011100011011110011111101011001",2)
    cipher = int("1011101101001011",2)

    print('key\t\t', bin(key))
    print('plaintext\t', bin(plain))

    my_IDEA = IDEA(key)
    encrypted = my_IDEA.encrypt(plain)
    decrypted = my_IDEA.decrypt(encrypted)

    print ('ciphertext\t', bin(encrypted))
    print ('decrypted\t', bin(decrypted))
    # assert cipher == encrypted
    # assert decrypted == plain


if __name__ == '__main__':
    main()
