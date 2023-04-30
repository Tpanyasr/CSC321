from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from hashlib import sha256
import hashlib
import random 
import task1


def generate_key_pair(n_bits):
    p = getPrime(n_bits)
    q = getPrime(n_bits)
    n = p * q
    Eulertotient = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, Eulertotient)
    return ((e, n), (d, n))

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)


def rsa_encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)



def part2():
    #Alice sends n, e
    publicKey, privateKey = generate_key_pair(2048)
    d,n = privateKey
    e,n = publicKey
    #bob computes s which is an integer less than n(product of the two primes)
    s = random.randrange(1, n)
    c = pow(s, e, n)
    #bob sends the value of c, but now mallory is able to intercept the value of c before it
    # reaches alice
    #mallory makes use of the mathematic function   f = (c % 2) 

    c_prime = c % 2

    s = pow(c_prime, d, n)
    s_toBytes = c_prime.to_bytes((c_prime.bit_length() + 7) // 8, byteorder='big')
    k = sha256(s_toBytes).digest()[:16]

    m = bytes("Hi Bob!", encoding='utf-8')
    c0 = task1.encrypt_message(k, m)
    
    malloryGuessKey1 = 0
    malloryGuessKey2 = 1
    #now because mallory knows that any number mod 2 is either 1 or 0 she just has to guess twice and see which one decrypts the message
    #between 1 or 0
    secret_Mallory1 = malloryGuessKey1.to_bytes((malloryGuessKey1.bit_length() + 7) // 8, byteorder='big')
    secret_Mallory2 = malloryGuessKey2.to_bytes((malloryGuessKey2.bit_length() + 7) // 8, byteorder='big')
    MalloryByteKey1 = sha256(secret_Mallory1).digest()[:16]
    MalloryByteKey2 = sha256(secret_Mallory2).digest()[:16]
    malDecrypt_c0_1 = task1.decrypt_message(MalloryByteKey1, c0)
    malDecrypt_c0_2 = task1.decrypt_message(MalloryByteKey2, c0)
    print(malDecrypt_c0_1)
    print(malDecrypt_c0_2)
   



message = random.randrange(100, 1000)
publicKey, privateKey = generate_key_pair(2048)
ciphertext = rsa_encrypt(message, publicKey)
decrypted = rsa_decrypt(ciphertext, privateKey)
print(message)
print(decrypted)

part2()
