from PIL import Image
import numpy as np
import io
from des import DesKey


def image_to_byte_array(image:Image, dimensions, format='PNG', block_size=64):
    imgByteArr = io.BytesIO()
    image.save(imgByteArr, format=format)
    imgByteArr = imgByteArr.getvalue()

    # Add padding if necessary
    pad_len = len(imgByteArr) % block_size//8
    for i in range(pad_len):
        imgByteArr += b'\x00'
   
    # Add infomation block about padding and image size
    width, height = dimensions
    info_block = bytearray()
    info_block += width.to_bytes(2, byteorder='big')
    info_block += height.to_bytes(2, byteorder='big')
    info_block += pad_len.to_bytes(1, byteorder='big')

    info_pad = (block_size // 8) - len(info_block)
    for i in range(info_pad):
        info_block += b'\x00'
    
    imgByteArr = imgByteArr + info_block
    
    return imgByteArr


def load_image_bytes(image_path):
    # Open the image and convert it to byte array
    image = Image.open(image_path)
    # Get image size
    width, height = image.size

    byte_array = image_to_byte_array(image, (width, height))

    # Convert the byte array to a numpy array
    np_array = np.frombuffer(byte_array, dtype=np.uint8)
    #img_format = image.format

    return np_array


# Initial permutation - permute key bit locations
def key_permutation(key):
    # Permutation Choice 1 (PC-1) table
    PC_1 = [
        56, 48, 40, 32, 24, 16, 8,
        0, 57, 49, 41, 33, 25, 17,
        9, 1, 58, 50, 42, 34, 26,
        18, 10, 2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
        6, 61, 53, 45, 37, 29, 21,
        13, 5, 60, 52, 44, 36, 28,
        20, 12, 4, 27, 19, 11, 3
    ]

    permuted = [key[i] for i in PC_1]
    return permuted

def key_compression(key):
    PC_2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    compressed = [key[i] for i in PC_2]
    return compressed

# Key transformation - shift key bits left for each round
def key_transformation(left, right, round):
    # amount to shift each half (28 bits) of the key each round
    round_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    # shift each half of the key
    right_shifted = np.roll(right, -round_shifts[round])
    left_shifted = np.roll(left, -round_shifts[round])

    return left_shifted.tolist(), right_shifted.tolist()

# Expansion permutation
def expansion(block):
    expansion_table = [
        31,  0,  1,  2,  3,  4,
        3,  4,  5,  6,  7,  8,
        7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    ]
    
    expanded = [block[i] for i in expansion_table]
    return expanded

# xor two blocks of bits
def xor(block1, block2):
    return [x ^ y for x, y in zip(block1, block2)]

# s box substitution
def s_box(block):
    sub_box = [    
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],  

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ], 

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ], 

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ]
    ]

    s_boxes = []
    # s box splits the 48 bits into eight groups of six bits, and each group gets ran through the s box
    for i in range(0, 48, 6):
        # Get the current 6 bits as input for the s box
        # Bits 1 and 6 are the row number - binary index is converted to int
        # Bits 2-5 are the column number - binary index is converted to int
        row_1_6 = int(str(block[i]) + str(block[i+5]), 2)
        col_2_5 = int(''.join([str(b) for b in block[i+1:i+5]]), 2)
        # Get the value from the s box
        bin_val = bin(sub_box[i // 6][row_1_6][col_2_5])[2:].zfill(4)
        s_boxes.extend([int(b) for b in bin_val])
    return s_boxes

def p_box(block):
    P = [
        15, 6, 19, 20, 28, 11, 27, 16, 
        0, 14, 22, 25, 4, 17, 30, 9, 
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]

    permuted = [block[i] for i in P]
    return permuted
    

def final_permutation(block):
    FP = [
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	]
    
    permuted = [block[i] for i in FP]
    return permuted

def key_generation(key):
    # Initial permutation
    key_p = key_permutation(key)

    # Split key into two halves
    left, right = key_p[:28], key_p[28:]

    sub_keys = []
    # 16 rounds
    for round in range(16):
        left, right = key_transformation(left, right, round)
        compressed = key_compression(left + right)
        sub_keys.append(compressed)
        
    return sub_keys

def initial_permutation(block):
    IP = [
        57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
    ]
    
    permuted = [block[i] for i in IP]
    return permuted


def des(key, pt_block, mode='encrypt'):
    # Check for valid inputs
    if mode not in ['encrypt', 'decrypt']:
        raise ValueError("Invalid mode. Choose 'encrypt' or 'decrypt'")
    if len(key) != 64:
        raise ValueError("Key must be 64 bits")
    if len(pt_block) != 64:
        raise ValueError("Block must be 64 bits")
    # Generate subkeys
    sub_keys = key_generation(key)
    # Inital permutation
    init_perm = initial_permutation(pt_block)
    # Split block into two halves
    left, right = init_perm[:32], init_perm[32:]
    # 16 rounds of encryption
    for round in range(16):
        # Start from the last round key if decrypting
        if mode == 'decrypt':
            round = 15 - round
        # Expansion permutation
        expanded = expansion(right)
        # XOR with round key
        xor_right = xor(expanded, sub_keys[round])
        # Substitution boxes
        s_boxes = s_box(xor_right)
        # Permutation
        permuted = p_box(s_boxes)
        # XOR with left half
        xor_left = xor(permuted, left)
        # Swap left and right and assign right with xor result
        left = right
        right = xor_left

    # Final permutation
    final_permute = final_permutation(right + left)
    return final_permute


def bytes_to_bits_binary(byte_data):
    bits_data = bin(int.from_bytes(byte_data, byteorder='big'))[2:]
    return bits_data

def des_cbc_enc(iv, key, text):
    print(len(text))
    # Convert key to binary and pad with zeros
    bin_key = ''.join([bin(byte)[2:].zfill(8) for byte in key])
    bin_key = [int(i, 2) for i in bin_key]
    if len(bin_key) < 64:
        bin_key.extend([0 for i in range(64 - len(bin_key))])
    #print("bin_key: ", bin_key)
    #print(len(bin_key))
    # Convert plaintext to binary
    #bin_text = [int(i, 2) for i in bin(bytes)[2:]]
    """
    bin_text = ''.join([bin(byte)[2:].zfill(8) for byte in text])
    print("bin_text: ", len(bin_text))
    bin_text = [int(i, 2) for i in bin_text]
    print("bin next: ", len(bin_text))
    """
    # Each block is 64 bits, so cut off the last block if it's less than 64 bits and pad with zeros
    #buffer = 64 - len(bin_text) % 64
    #if len(bin_text) % 64 != 0:
    #    bin_text.extend([ 0 for i in range((64 - len(bin_text) % 64))])
    bin_text = text
    # Split plaintext into blocks
    blocks = [bin_text[i:i+64] for i in range(0, len(bin_text), 64)]
    # XOR first block with iv
    crypted = []
    init_v = iv
    #blocks[0] = [x ^ y for x, y in zip(blocks[0], iv)]
    # Encrypt each block
    for i in range(len(blocks)):
        xor_res = [x ^ y for x, y in zip(blocks[i], init_v)]
        cipher_block = des(bin_key, xor_res, 'encrypt')
        crypted.append(cipher_block)
        init_v = cipher_block
        """
        blocks[i] = des(bin_key, blocks[i], 'encrypt')
        # XOR with previous block
        if i < len(blocks) - 1:
            blocks[i+1] = [x ^ y for x, y in zip(blocks[i], blocks[i+1])]
        """
    # Convert blocks to byte array
    #for block in blocks:
    #    byte_array.extend([int(''.join([str(b) for b in block[i:i+8]]), 2) for i in range(0, 64, 8)])
    #flattened = np.array(blocks).flatten()
    #print("blocks: ", np.array(blocks).flatten())
    flat_blocks = np.array(crypted).flatten()#[:-buffer]
    #byte_blocks = np.array([int(''.join([str(b) for b in flat_blocks[i:i+8]]), 2) for i in range(0, len(flat_blocks), 8)])
    return flat_blocks

def des_cbc_dec(iv, key, text):
    print(len(text))
    # Convert key to binary and pad with zeros
    bin_key = ''.join([bin(byte)[2:].zfill(8) for byte in key])
    bin_key = [int(i, 2) for i in bin_key]
    if len(bin_key) < 64:
        bin_key.extend([0 for i in range(64 - len(bin_key))])
    #print("bin_key: ", bin_key)
    #print(len(bin_key))
    # Convert plaintext to binary
    #bin_text = [int(i, 2) for i in bin(bytes)[2:]]
    """
    bin_text = ''.join([bin(byte)[2:].zfill(8) for byte in text])
    print("bin_text: ", len(bin_text))
    bin_text = [int(i, 2) for i in bin_text]
    print("bin next: ", len(bin_text))
    """
    # Each block is 64 bits, so cut off the last block if it's less than 64 bits and pad with zeros
    #buffer = 64 - len(bin_text) % 64
    #if len(bin_text) % 64 != 0:
    #    bin_text.extend([ 0 for i in range((64 - len(bin_text) % 64))])
    bin_text = text
    # Split plaintext into blocks
    blocks = [bin_text[i:i+64] for i in range(0, len(bin_text), 64)]
    # XOR first block with iv
    crypted = []
    init_v = iv
    #blocks[0] = [x ^ y for x, y in zip(blocks[0], iv)]
    # Encrypt each block
    for i in range(len(blocks)):
        cipher_block = des(bin_key, blocks[i], 'decrypt')
        xor_res = [x ^ y for x, y in zip(cipher_block, init_v)]
        crypted.append(xor_res)
        init_v = blocks[i]
        """
        blocks[i] = des(bin_key, blocks[i], 'encrypt')
        # XOR with previous block
        if i < len(blocks) - 1:
            blocks[i+1] = [x ^ y for x, y in zip(blocks[i], blocks[i+1])]
        """
    # Convert blocks to byte array
    #for block in blocks:
    #    byte_array.extend([int(''.join([str(b) for b in block[i:i+8]]), 2) for i in range(0, 64, 8)])
    #flattened = np.array(blocks).flatten()
    #print("blocks: ", np.array(blocks).flatten())
    flat_blocks = np.array(crypted).flatten()#[:-buffer]
    #byte_blocks = np.array([int(''.join([str(b) for b in flat_blocks[i:i+8]]), 2) for i in range(0, len(flat_blocks), 8)])
    return flat_blocks




if __name__ == '__main__':
    image = load_image_bytes('doge.png')
    #key = [int(i, 2) for i in  bin(int("0123456789ABCDEF", 16))[2:].zfill(64)]
    #"""
    key = b'key'
    iv = [0 for i in range(64)]
    #print(image)
    print("image: ", image[:20])
    print("image length: ", len(image))
    test = "this is a test string to see if this works "
    bits = [int(i, 2) for i in ''.join(format(ord(char), '08b') for char in test)]
    original = bits[:]
    print(bits)
    pad = 64 - len(bits) % 64
    if len(bits) % 64 != 0:
        bits.extend([0 for i in range(64 - len(bits) % 64)])
    encrypted = des_cbc_enc(iv, key, bits)

    print("encrypted: ", encrypted[:20])
    print("encrypted length: ", len(encrypted))
    binary_string = ''.join(map(str, encrypted))
    text = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    print("encrypted: ", text)

    decrypted = des_cbc_dec(iv, key, encrypted)
    print("decrypted: ", decrypted[:20])

    decrypted = decrypted[:-pad]
    binary_string = ''.join(map(str, decrypted))
    text = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    print("text: ", text)

    #"""
    #print("decrypted same as image: ", decrypted == image)
    #img = Image.open(io.BytesIO(decrypted))
    #img = Image.frombytes('RGB', (width, height), image)
    #img.show()
