from PIL import Image
import numpy as np
import io

def image_to_byte_array(image:Image, format='PNG'):
  imgByteArr = io.BytesIO()
  image.save(imgByteArr, format=format)
  imgByteArr = imgByteArr.getvalue()
  return imgByteArr


def encrypt(image_path, key):
    # Open the image and convert it to byte array
    image = Image.open(image_path)
    byte_array = image_to_byte_array(image)

    # Convert the byte array to a numpy array
    np_array = np.frombuffer(byte_array, dtype=np.uint8)


# Initial permutation - permute key bit locations
def initial_permutation(key):
    # Permutation Choice 1 (PC-1) table
    PC_1 = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    """
    57, 49, 41, 33, 25, 17, 9
    1, 58, 50, 42, 34, 26, 18
    10, 2, 59, 51, 43, 35, 27
    19, 11, 3, 60, 52, 44, 36
    63, 55, 47, 39, 31, 23, 15
    7, 62, 54, 46, 38, 30, 22
    14, 6, 61, 53, 45, 37, 29
    21, 13, 5, 28, 20, 12, 4
    """
    permuted = np.zeros(64)

    # swap each bit location in the block with the corresponding index in the permutation table
    for i in range(len(key)):
        permuted[i] = key[PC_1[i] - 1]

    return permuted[:56]


def key_transformation(left, right, round):
    # amount to shift each half (28 bits) of the key each round
    round_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    # shift each half of the key
    right_shifted = np.roll(right, -round_shifts[round])
    left_shifted = np.roll(left, -round_shifts[round])

    return left_shifted, right_shifted


def key_compression(key):
    PC_2 = [

    ]


def des(key, plaintext):
    # Initial permutation
    key_p = initial_permutation(key)

    # Split key into two halves
    left = key_p[:28]
    right = key_p[28:]

    # 16 rounds
    for round in range(16):
        left, right = key_transformation(left, right, round)

    # Final permutation
    key = np.concatenate((left, right))

    return key


def encrypt(image_path, key):
    pass

if __name__ == '__main__':
    key = list("0001001100110100010101110111100110011011101111001101111111110001")
    print(initial_permutation(key))