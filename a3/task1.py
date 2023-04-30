from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from hashlib import sha256
import random


def pad_message(message):
    padding_len = AES.block_size - (len(message) % AES.block_size)
    padding = bytes([padding_len] * padding_len)
    return message + padding

def unpad_message(message):
    padding_len = message[-1]
    return message[:-padding_len]

def encrypt_message(key, message):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad_message(message)
    ciphertext = cipher.encrypt(padded_message)
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad_message(padded_plaintext)
    return plaintext


def dhellman(q, alpha):
    # private key selection
    #rand range used to get Xa and Xb < q
    Xa = random.randrange(0, q)
    Xb = random.randrange(0, q)
    #public key generation
    # Alice: Ya = g^a mod p,   Bob: Yb = g^b mod p
    Ya = alpha^(Xa) %q
    Yb = alpha^(Xb) %q
    #shared secret calculation
    Ka = (Ya)^Xa %q
    Kb = (Yb)^Xb %q
    #print(Ka, Kb)
    # Convert shared secret to bytes
    shared_secret_bytes = Ka.to_bytes((Ka.bit_length() + 7) // 8, byteorder='big')
    # Hash the shared secret using SHA-256 and truncate to 16 bytes
    secretKey = sha256(shared_secret_bytes).digest()[:16]

    # Alice encrypts a message to Bob
    m0 = bytes("Hi Bob!", encoding='utf-8')
    c0 = encrypt_message(secretKey, m0)

    # Bob decrypts the message from Alice
    m0_decrypted = decrypt_message(secretKey, c0)

    # Bob encrypts a message to Alice
    m1 = bytes("Hi Alice!", encoding='utf-8')
    c1 = encrypt_message(secretKey, m1)

    # Alice decrypts the message from Bob
    m1_decrypted = decrypt_message(secretKey, c1)

    print("Alice recieved: ", m1_decrypted)
    print("Bob recieved: ", m0_decrypted)



# dhellman(37, 5)
q_hex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
q_int = int(q_hex, 16)

alpha_hex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
alpha_int = int(alpha_hex, 16)

dhellman(q_int, alpha_int)
