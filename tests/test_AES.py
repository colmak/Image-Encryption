import unittest
from PIL import Image
import numpy as np
import AES



class TestAESEncryption(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        self.test_string = bytes.fromhex('00000101030307070f0f1f1f3f3f7f7f')
        self.byte_array = bytearray(self.test_string)
        self.np_array = np.frombuffer(self.byte_array, dtype=np.uint8)
        self.state = self.np_array.reshape((4, 4))

def test_sub_bytes(self):
    # Define a known state
    state = np.array([
        [0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34]
    ])

    # Apply the sub_bytes function
    result = AES.sub_bytes(state, AES.s_box)

    # Define the expected result
    expected_result = np.array([
        [0xe5, 0x9c, 0x17, 0x2b],
        [0xd6, 0x12, 0x17, 0x39],
        [0x3e, 0x3c, 0x1e, 0x84],
        [0x5e, 0x1f, 0x4d, 0x7c]
    ])

    # Check that the result matches the expected result
    self.assertTrue(np.array_equal(result, expected_result))

    def test_shift_rows(self):
        result = AES.shift_rows(self.state)
        # Add your assertions here

    def test_mix_columns(self):
        result = AES.mix_columns(self.state)
        # Add your assertions here

    def test_add_round_key(self):
        result = AES.add_round_key(self.state, self.key)
        # Add your assertions here

    def test_full_encryption(self):
        # Test the full encryption process
        encrypted = AES.encrypt(self.test_string, self.key)

if __name__ == '__main__':
    unittest.main()