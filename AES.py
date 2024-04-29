"""
AES Encryption and Decryption in CBC Mode
By Roland Van Duine
"""

from collections import deque
import operator
import os
from PIL import Image
import io
from typing import List
import math

# reference
# https://www.youtube.com/watch?v=O4xNJsjtN6E&ab_channel=Computerphile
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
# https://www.youtube.com/watch?v=vVtYYMU3koM&ab_channel=CyrillG%C3%B6ssi

def image_to_byte_array(image:Image):
    """
    Image to byte array
    """
    imgByteArr = io.BytesIO()
    image.save(imgByteArr, format='PNG')
    imgByteArr = imgByteArr.getvalue()
    return bytearray(imgByteArr)


def byte_array_to_image(byte_array, image_format='PNG',filename='recovered.png'):
    """
    Byte array to image
    """
    image = Image.open(io.BytesIO(byte_array))
    image_path = os.path.join(os.getcwd(), filename)
    image.save(image_path)
    return image_path

def encrpyted_byte_array_to_image(byte_array, mode='RGB', image_format='PNG', filename='test2.png'):
    """
    Encrypted byte array to image
    """
    size = int(math.sqrt(len(byte_array) / 3)) 
    image = Image.frombytes(mode, (size, size), bytes(byte_array))
    image_path = os.path.join(os.getcwd(), filename)
    image.save(image_path)
    return image_path

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
    """Calculate the round constant for a given round in the AES algorithm."""
    rcon_lookup = [
        bytes([0, 0, 0, 0]),
        bytes([1, 0, 0, 0]),
        bytes([2, 0, 0, 0]),
        bytes([4, 0, 0, 0]),
        bytes([8, 0, 0, 0]),
        bytes([16, 0, 0, 0]),
        bytes([32, 0, 0, 0]),
        bytes([64, 0, 0, 0]),
        bytes([128, 0, 0, 0]),
        bytes([27, 0, 0, 0]),
        bytes([54, 0, 0, 0]),
    ]

    return rcon_lookup[i]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    This function takes two bytes objects as input and returns a new bytes object
    that is the result of a bitwise XOR operation on the input bytes.
    """
    return bytes(map(operator.xor, a, b))


def rot_word(word: List[int]) -> List[int]:
    """
    This function takes a list of integers (word) and rotates it to the left.
    The first element moves to the end of the list, and all other elements move one position to the left.
    """
    d = deque(word)
    d.rotate(-1)
    return list(d)


def key_expansion(key: bytes, num_columns: int = 4) -> List[List[List[int]]]:

    """
    Performs the key expansion step of the AES algorithm. 
    Takes a key (bytes) and number of columns in the state (default 4) as input. 
    Expands the key into a key schedule, a list of round keys. 
    The key expansion involves deriving an initial state from the key 
    and then generating additional words based on the key length and their position in the key schedule. 

    """
    key_length = len(key) // 4

    num_rounds = 10
    
    state = state_from_bytes(key)

    for index in range(key_length, num_columns * (num_rounds + 1)):
        temp_word = state[index-1]
        if index % key_length == 0:
            temp_word = xor_bytes(sub_word(rot_word(temp_word)), rcon(index // key_length))
        elif key_length > 6 and index % key_length == 4:
            temp_word = sub_word(temp_word)
        state.append(xor_bytes(state[index - key_length], temp_word))

    return [state[i*4:(i+1)*4] for i in range(len(state) // 4)]


def add_round_key(state: List[List[int]], key_schedule: List[List[List[int]]], round: int):
    """
    This function performs the AddRoundKey step in the AES algorithm.
    It takes the current state, the key schedule, and the current round number as inputs.
    The function XORs the state with the round key from the key schedule for the given round.
    The state is modified in-place.
    """
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [s ^ k for s, k in zip(state[r], round_key[r])]

def sub_bytes(state: List[List[int]]):
    """
    This function performs the SubBytes step in the AES algorithm.
    It takes the current state as input and replaces each byte in the state
    with its corresponding byte in the substitution box (s_box).
    The state is modified in-place.
    """
    for r in range(len(state)):
        state[r] = list(map(lambda c: s_box[c], state[r]))
        
        

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
        # If the 8th bit is set, shift 'a' to the left by 1 (i.e., multiply it by 2),
        # perform a bitwise XOR with 0x1B, and mask the result to 1 byte
        return ((a << 1) ^ 0x1b) & 0xff
    else:
        # If the 8th bit is not set, simply shift 'a' to the left by 1 (i.e., multiply it by 2)
        return a << 1


def mix_column(col: List[int]):
    """
    Performs the mix_column operation in the AES encryption algorithm.
    
    The function takes a column of the state matrix as input and applies a series of XOR and xtime operations 
    to each element. The result is a new column where each element is influenced by all elements of the input column, 
    providing the diffusion property of the AES algorithm.
    """
    first_element = col[0]
    xor_of_all_elements = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= xor_of_all_elements ^ xtime(col[0] ^ col[1])
    col[1] ^= xor_of_all_elements ^ xtime(col[1] ^ col[2])
    col[2] ^= xor_of_all_elements ^ xtime(col[2] ^ col[3])
    col[3] ^= xor_of_all_elements ^ xtime(first_element ^ col[3])



def mix_columns(state: List[List[int]]):
    """
    Mix all columns of the state matrix using the mix_column operation.
    """
    for r in state:
        mix_column(r)



def state_from_bytes(data: bytes) -> List[List[int]]:
    """
    Converts a byte array into a list of 4-byte blocks.

    Takes a byte array as input and returns a list of byte arrays,
    each of length 4. Dividing the input byte array into blocks of 4 bytes
    """
    state = [data[i*4:(i+1)*4] for i in range(len(data) // 4)]
    return state


def bytes_from_state(state: List[List[int]]) -> bytes:
    """
    Return a byte array from a state matrix.
    """
    return bytes(state[0] + state[1] + state[2] + state[3])


def aes_encryption(data: bytes, key: bytes) -> bytes:
    """
    AES encryption algorithm.
    10 rounds for 128-bit key.
    for each round:
        - sub_bytes
        - shift_rows
        - mix_columns
        - add_round_key
    and final round
        - sub_bytes
        - shift_rows
        - add_round_key
    """

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
    """
    Perform the inverse ShiftRows operation on the state matrix.
    """
    state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
    state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
    state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]
    return

# Inverse S-box for the AES algorithm                   
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
    """
    Inverse SubBytes operation in the AES decryption algorithm.
    """
    for r in range(len(state)):
        state[r] = [inv_s_box[state[r][c]] for c in range(len(state[0]))]


def xtimes(b: int, op: str):
    """
    xtimes operation in the AES decryption algorithm.
    Xtimes is a multiplication operation in the Galois field.
    """
    if op == '0e':
        # 0x0e = 14 = b1110 = ((x * 2 + x) * 2 + x) * 2
        return xtime(xtime(xtime(b) ^ b) ^ b)
    elif op == '0b':
        # 0x0b = 11 = b1011 = ((x*2)*2+x)*2+x
        return xtime(xtime(xtime(b)) ^ b) ^ b
    elif op == '0d':
        # 0x0d = 13 = b1101 = ((x*2+x)*2)*2+x
        return xtime(xtime(xtime(b) ^ b)) ^ b
    elif op == '09':
        # 0x09 = 9  = b1001 = ((x*2)*2)*2+x
        return xtime(xtime(xtime(b))) ^ b
    else:
        raise ValueError("Invalid operation")



def inv_mix_column(col: List[int]):
    """
    Inverse mix_column operation in the AES decryption algorithm.
    """
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
    col[0] = xtimes(c_0, '0e') ^ xtimes(c_1, '0b') ^ xtimes(c_2, '0d') ^ xtimes(c_3, '09')
    col[1] = xtimes(c_0, '09') ^ xtimes(c_1, '0e') ^ xtimes(c_2, '0b') ^ xtimes(c_3, '0d')
    col[2] = xtimes(c_0, '0d') ^ xtimes(c_1, '09') ^ xtimes(c_2, '0e') ^ xtimes(c_3, '0b')
    col[3] = xtimes(c_0, '0b') ^ xtimes(c_1, '0d') ^ xtimes(c_2, '09') ^ xtimes(c_3, '0e')


def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    """
    Inverse mix_columns operation in the AES decryption algorithm.
    """
    for r in state:
        inv_mix_column(r)

def aes_decryption(cipher: bytes, key: bytes) -> bytes:
    """
    AES decryption algorithm.
    10 rounds for 128-bit key.
    for each round:
        - inv_shift_rows
        - inv_sub_bytes
        - add_round_key
        - inv_mix_columns
    and final round
        - inv_shift_rows
        - inv_sub_bytes
        - add_round_key
    """
    
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
    """
    AES encryption in CBC mode.
    1. Divide the plaintext into blocks of 16 bytes.
    2. XOR the first block with the IV.
    3. Encrypt the XORed block using AES.
    4. XOR the encrypted block with the IV.
    5. Repeat steps 2-4 for the remaining blocks.
    6. Return the ciphertext.
    """

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
    """
    AES decryption in CBC mode.
    1. Divide the ciphertext into blocks of 16 bytes.
    2. Decrypt the first block using AES.
    3. XOR the decrypted block with the IV.
    4. Repeat steps 2-3 for the remaining blocks.
    5. Return the plaintext.
    """

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