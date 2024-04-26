from PIL import Image
import numpy as np
import io
import re
from typing import List
import math

# reference
# https://www.youtube.com/watch?v=O4xNJsjtN6E&ab_channel=Computerphile
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

def image_to_byte_array(image:Image):
    imgByteArr = io.BytesIO()
    image.save(imgByteArr, format='PNG')
    imgByteArr = imgByteArr.getvalue()

    # # Add padding if necessary
    # while len(imgByteArr) % 16 != 0:
    #     imgByteArr += b'\x00'

    # Convert bytes to bytearray before returning
    return bytearray(imgByteArr)


def byte_array_to_image(byte_array, image_format='PNG',filename='recovered.png'):
    image = Image.open(io.BytesIO(byte_array))
    image.save(filename, format=image_format)
    return image

def encrpyted_byte_array_to_image(byte_array, mode='RGB', image_format='PNG', filename='test2.png'):
    # Calculate the size of the image
    size = int(math.sqrt(len(byte_array) / 3))  # Divide by 3 for RGB images

    image = Image.frombytes(mode, (size, size), bytes(byte_array))
    image.save(filename, format=image_format)
    return image

# Subsitiion table for the AES algorithm
s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


def sub_word(word: List[int]) -> bytes:
    """
    This function performs a byte substitution on a given word using a substitution box (s_box).
    It takes a list of integers (word) as input and returns a new bytes object where each byte in the input word
    has been replaced by the corresponding byte in the substitution box.
    """
    substituted_word = bytes(s_box[i] for i in word)
    return substituted_word


def rcon(i: int) -> bytes:
    """
    This function returns the round constant for a given round in the AES algorithm.
    The round constants are a series of values derived from the powers of 2 in the Galois field.
    These constants are used in the key expansion phase of the AES algorithm.
    """
    rcon_lookup = bytearray.fromhex('01020408102040801b36')
    rcon_value = bytes([rcon_lookup[i-1], 0, 0, 0])
    return rcon_value


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    This function takes two bytes objects as input and returns a new bytes object
    that is the result of a bitwise XOR operation on the input bytes.
    """
    return bytes([x ^ y for (x, y) in zip(a, b)])


def rot_word(word: List[int]) -> List[int]:
    """
    This function takes a list of integers (word) and rotates it to the left.
    The first element moves to the end of the list, and all other elements move one position to the left.
    """
    return word[1:] + word[:1]


def key_expansion(key: bytes, nb: int = 4) -> List[List[List[int]]]:

    nk = len(key) // 4

    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    else:  # 256-bit keys
        nr = 14

    w = state_from_bytes(key)

    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i - nk], temp))

    return [w[i*4:(i+1)*4] for i in range(len(w) // 4)]


def add_round_key(state: List[List[int]], key_schedule: List[List[List[int]]], round: int):
    """
    This function performs the AddRoundKey step in the AES algorithm.
    It takes the current state, the key schedule, and the current round number as inputs.
    The function XORs the state with the round key from the key schedule for the given round.
    The state is modified in-place.
    """
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]

def sub_bytes(state: List[List[int]]):
    """
    This function performs the SubBytes step in the AES algorithm.
    It takes the current state as input and replaces each byte in the state
    with its corresponding byte in the substitution box (s_box).
    The state is modified in-place.
    """
    for r in range(len(state)):
        state[r] = [s_box[state[r][c]] for c in range(len(state[0]))]
        
        

def shift_rows(state: List[List[int]]):
    """
    This function performs the ShiftRows step in the AES algorithm.
    It takes the current state as input and shifts the rows of the state matrix
    according to the AES specification.
    The state is modified in-place.
    """
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


def xtime(a: int) -> int:
    """
    This function performs the xtime operation in the AES algorithm.
    It takes an integer as input and multiplies it by 2 in the Galois field.
    If the input integer is greater than 127 (0x7F), it also performs a bitwise XOR with 0x1B and masks the result to 1 byte.
    """
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1


def mix_column(col: List[int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= all_xor ^ xtime(col[0] ^ col[1])
    col[1] ^= all_xor ^ xtime(col[1] ^ col[2])
    col[2] ^= all_xor ^ xtime(col[2] ^ col[3])
    col[3] ^= all_xor ^ xtime(c_0 ^ col[3])



def mix_columns(state: List[List[int]]):
    for r in state:
        mix_column(r)



def state_from_bytes(data: bytes) -> List[List[int]]:
    """
    Converts a byte array into a list of 4-byte blocks.

    This function takes a byte array as input and returns a list of byte arrays,
    each of length 4. Dividing the input byte array into blocks of 4 bytes
    """
    state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
    return state


def bytes_from_state(state: List[List[int]]) -> bytes:
    return bytes(state[0] + state[1] + state[2] + state[3])


def aes_encryption(data: bytes, key: bytes) -> bytes:

    nr = 10

    state = state_from_bytes(data)
    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule, round=0)

    for round in range(1, nr):
        
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    cipher = bytes_from_state(state)
    return cipher


def inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] <-- [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
    state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
    state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]
    return

                   
inv_s_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]



def inv_sub_bytes(state: List[List[int]]) -> List[List[int]]:
    for r in range(len(state)):
        state[r] = [inv_s_box[state[r][c]] for c in range(len(state[0]))]


def xtimes_0e(b):
    # 0x0e = 14 = b1110 = ((x * 2 + x) * 2 + x) * 2
    return xtime(xtime(xtime(b) ^ b) ^ b)


def xtimes_0b(b):
    # 0x0b = 11 = b1011 = ((x*2)*2+x)*2+x
    return xtime(xtime(xtime(b)) ^ b) ^ b


def xtimes_0d(b):
    # 0x0d = 13 = b1101 = ((x*2+x)*2)*2+x
    return xtime(xtime(xtime(b) ^ b)) ^ b


def xtimes_09(b):
    # 0x09 = 9  = b1001 = ((x*2)*2)*2+x
    return xtime(xtime(xtime(b))) ^ b


def inv_mix_column(col: List[int]):
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
    col[0] = xtimes_0e(c_0) ^ xtimes_0b(c_1) ^ xtimes_0d(c_2) ^ xtimes_09(c_3)
    col[1] = xtimes_09(c_0) ^ xtimes_0e(c_1) ^ xtimes_0b(c_2) ^ xtimes_0d(c_3)
    col[2] = xtimes_0d(c_0) ^ xtimes_09(c_1) ^ xtimes_0e(c_2) ^ xtimes_0b(c_3)
    col[3] = xtimes_0b(c_0) ^ xtimes_0d(c_1) ^ xtimes_09(c_2) ^ xtimes_0e(c_3)


def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    for r in state:
        inv_mix_column(r)


def inv_mix_column_optimized(col: List[int]):
    u = xtime(xtime(col[0] ^ col[2]))
    v = xtime(xtime(col[1] ^ col[3]))
    col[0] ^= u
    col[1] ^= v
    col[2] ^= u
    col[3] ^= v


def inv_mix_columns_optimized(state: List[List[int]]) -> List[List[int]]:
    for r in state:
        inv_mix_column_optimized(r)
    mix_columns(state)


def aes_decryption(cipher: bytes, key: bytes) -> bytes:
    nr = 10

    state = state_from_bytes(cipher)
    key_schedule = key_expansion(key)
    add_round_key(state, key_schedule, round=nr)

    for round in range(nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, round=0)

    plain = bytes_from_state(state)
    return plain


def aes_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes) -> bytes:

    ciphertext = []

    first_block = plaintext[:16]
    encrypted_first_block = aes_encryption(xor_bytes(first_block, iv), key)
    ciphertext += encrypted_first_block

    previous_ciphertext_block = encrypted_first_block
    for block_index in range(1, len(plaintext) // 16):
        plaintext_block = plaintext[block_index*16:(block_index+1)*16]
        encrypted_block = aes_encryption(xor_bytes(plaintext_block, previous_ciphertext_block), key)
        ciphertext += encrypted_block
        previous_ciphertext_block = encrypted_block

    return bytes(ciphertext)


def aes_cbc_decryption(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:

    plaintext = []

    first_ciphertext_block = ciphertext[:16]
    decrypted_first_block = aes_decryption(first_ciphertext_block, key)
    plaintext_first_block = xor_bytes(decrypted_first_block, iv)
    plaintext += plaintext_first_block

    previous_ciphertext_block = first_ciphertext_block
    for block_index in range(1, len(ciphertext) // 16):
        ciphertext_block = ciphertext[block_index*16:(block_index+1)*16]
        decrypted_block = aes_decryption(ciphertext_block, key)
        plaintext_block = xor_bytes(decrypted_block, previous_ciphertext_block)
        plaintext += plaintext_block
        previous_ciphertext_block = ciphertext_block

    return bytes(plaintext)



if __name__ == "__main__":
    # Load an image and convert it to a byte array
    image = Image.open('test.png')
    plaintext = image_to_byte_array(image)

    # # Convert the byte array to a hexadecimal string
    # hex_string = binascii.hexlify(plaintext).decode()

    # # Split the hexadecimal string into chunks of 32 characters
    # chunks = [hex_string[i:i+32] for i in range(0, len(hex_string), 32)]

    # # Join the chunks with line breaks to match the given format
    # formatted_hex_string = "'".join(chunks)

    # # Add the opening and closing quotes
    # formatted_hex_string = "'" + formatted_hex_string + "'"

    # print(f"Plaintext: {plaintext.hex()[:100]}...")

    # plaintext = bytearray.fromhex('00112233445566778899aabbccddeefd')
    # # AES key must be either 16 bytes long
    # key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')

    # # Perform AES encryption on the byte array
    # ciphertext = aes_encryption(plaintext, key)
    # print(f"AES-128 plaintext: {plaintext.hex()[:100]}...")
    # print(f"AES-128 ciphertext: {ciphertext.hex()[:100]}...")

    # # Perform AES decryption on the encrypted byte array
    # recovered_plaintext = aes_decryption(ciphertext, key)
    # print(f"AES-128 recovered plaintext: {recovered_plaintext.hex()[:100]}...")

    # # Assert that the recovered plaintext is the same as the original plaintext
    # assert (recovered_plaintext == plaintext)
    
    # NIST Special Publication 800-38A
    # plaintext = bytearray.fromhex('6bc1bee22e409f96e93d7e117393172a'
    #                               'ae2d8a571e03ac9c9eb76fac45af8e51'
    #                               '30c81c46a35ce411e5fbc1191a0a52ef'
    #                               'f69f2445df4f9b17ad2b417be66c3710')
    # print(plaintext)

    key = bytearray.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    
    iv = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')

    # expected_ciphertext = bytearray.fromhex('7649abac8119b246cee98e9b12e9197d'
    #                                         '5086cb9b507219ee95db113a917678b2'
    #                                         '73bed6b8e3c1743b7116e69e22229516'
    #                                         '3ff1caa1681fac09120eca307586e1a7')
    
    ciphertext = aes_cbc_encryption(plaintext, key, iv)
    # print(f"Actual ciphertext: {ciphertext.hex()}")
    # print(f"Expected ciphertext: {expected_ciphertext.hex()}")
    # assert (ciphertext == expected_ciphertext)


    recovered_plaintext = aes_cbc_decryption(ciphertext, key, iv)
    
    ciphertext_image = encrpyted_byte_array_to_image(ciphertext, filename='encrypted.png')
    recovered_image = byte_array_to_image(recovered_plaintext, filename='recovered.png')
    
    # assert (recovered_plaintext == plaintext)
    # print(f"Actual plaintext:    {plaintext.hex()}")
    # print(f"Recovered plaintext: {recovered_plaintext.hex()}")