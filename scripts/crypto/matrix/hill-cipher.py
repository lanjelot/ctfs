# Hill Cipher
# over the hill - icectf-2016
# can also use sage like in this other chall: https://github.com/ctfs/write-ups-2015/tree/master/ghost-in-the-shellcode-2015/crypto/nikoli
from sympy.crypto.crypto import encipher_hill, decipher_hill
from sympy import Matrix
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789_{}"
ciphertext = "7Nv7}dI9hD9qGmP}CR_5wJDdkj4CKxd45rko1cj51DpHPnNDb__EXDotSRCP8ZCQ"
matrix = Matrix([
    [54, 53, 28, 20, 54, 15, 12, 7],
    [32, 14, 24, 5, 63, 12, 50, 52],
    [63, 59, 40, 18, 55, 33, 17, 3],
    [63, 34, 5, 4, 56, 10, 53, 16],
    [35, 43, 45, 53, 12, 42, 35, 37],
    [20, 59, 42, 10, 46, 56, 12, 61],
    [26, 39, 27, 59, 44, 54, 23, 56],
    [32, 31, 56, 47, 31, 2, 29, 41]
])
print decipher_hill(ciphertext, matrix, alphabet)
