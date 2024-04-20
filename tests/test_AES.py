import unittest
import numpy as np
import AES

class TestAESEncryption(unittest.TestCase):
    def setUp(self):
        self.key = 'your-16-byte-key'
        self.image_path = 'path-to-your-test-image'
        self.image = Image.open(self.image_path)
        self.byte_array = AES.image_to_byte_array(self.image)
        self.np_array = np.frombuffer(self.byte_array, dtype=np.uint8)
        self.state = self.np_array.reshape((4, 4))

    def test_sub_bytes(self):
        result = AES.sub_bytes(self.state, AES.s_box)
        # Add your assertions here

    def test_shift_rows(self):
        result = AES.shift_rows(self.state)
        # Add your assertions here

    def test_mix_columns(self):
        result = AES.mix_columns(self.state)
        # Add your assertions here

    def test_add_round_key(self):
        result = AES.add_round_key(self.state, self.key)
        # Add your assertions here

    def test_encrypt(self):
        result = AES.encrypt(self.image_path, self.key)
        # Add your assertions here

if __name__ == '__main__':
    unittest.main()