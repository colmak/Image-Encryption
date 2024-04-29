import os
import random
import sys
import numpy as np

from PIL import Image
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QGridLayout, QSizePolicy, QSpacerItem
from PyQt5.QtGui import QPixmap, QImage, QIcon
from PyQt5.QtCore import Qt, QBuffer

import AES



class ImageEncryptor(QWidget):
    """A class to represent an image encryptor widget."""

    def __init__(self):
        """Initialize the widget."""
        super().__init__()

        self.initUI()

    def initUI(self):
            """Initialize the user interface."""
            self.layout = QVBoxLayout()
            self.layout.setContentsMargins(10, 10, 10, 10)  # Add margins
            self.setLayout(self.layout)

            self.uploadButton = QPushButton('Upload Image')
            self.uploadButton.clicked.connect(self.uploadImage)
            self.uploadButton.setStyleSheet("font-size: 20px")
            self.layout.addWidget(self.uploadButton)

            self.encryptButton = QPushButton('Encrypt and Decrypt Image')
            self.encryptButton.clicked.connect(self.encryptAndDecryptImage)
            self.encryptButton.hide()
            self.layout.addWidget(self.encryptButton)
            self.encryptButton.setStyleSheet("font-size: 20px")
            
            self.nextButton = QPushButton('Next')
            self.nextButton.clicked.connect(self.showNextImage)
            self.nextButton.hide()
            self.layout.addWidget(self.nextButton)
            self.nextButton.setStyleSheet("font-size: 20px")

            self.imageLabel = QLabel()
            self.imageLabel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding) 
            self.layout.addWidget(self.imageLabel)
            self.imageLabel.setStyleSheet("font-size: 20px")
            
            self.recoveredImageLabel = QLabel("Recovered Image")
            self.recoveredImageLabel.hide()
            self.layout.addWidget(self.recoveredImageLabel)
            self.recoveredImageLabel.setStyleSheet("font-size: 20px")



    def uploadImage(self):
        """Upload an image."""
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        fileName, _ = QFileDialog.getOpenFileName(self, "QFileDialog.getOpenFileName()", "", "All Files (*);;Python Files (*.py)", options=options)
        if fileName:
            pixmap = QPixmap(fileName)
            self.imageLabel.setPixmap(pixmap)
            self.encryptButton.show()
            self.uploadButton.hide()
            self.uploadedImagePath = fileName 

    def encryptAndDecryptImage(self):
            """Encrypt and decrypt an image."""
            if self.uploadedImagePath is None:
                print('No image uploaded')
                return

            print('Encrypting image...')
            image = Image.open(self.uploadedImagePath)  
            plaintext = AES.image_to_byte_array(image)
            
            key = bytearray.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
            iv = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
            
            ciphertext = AES.aes_cbc_encryption(plaintext, key, iv)
            recovered_plaintext = AES.aes_cbc_decryption(ciphertext, key, iv)

            # Generate a filename based on the uploaded image and two random digits
            base_name = os.path.basename(self.uploadedImagePath)
            base_name_without_ext = os.path.splitext(base_name)[0]
            random_digits = random.randint(10, 99)  # Generate two random digits
            new_filename = f"{base_name_without_ext}_{random_digits}"

            self.encryptedImagePath = AES.encrpyted_byte_array_to_image(ciphertext, filename=f'{new_filename}_encrypted.png')
            self.recoveredImagePath = AES.byte_array_to_image(recovered_plaintext, filename=f'{new_filename}_recovered.png')

            # Show the encrypted image
            self.imageLabel.setPixmap(QPixmap(self.encryptedImagePath))
            self.encryptButton.hide()
            self.nextButton.show()

            print('Encrypting complete')
            
    def showNextImage(self):
        """Show the next image."""
        if self.recoveredImagePath is not None:
            self.imageLabel.setPixmap(QPixmap(self.recoveredImagePath))
            self.nextButton.hide()
            self.recoveredImageLabel.show()

if __name__ == '__main__':
    app = QApplication(sys.argv)

    window = ImageEncryptor()
    window.show()

    sys.exit(app.exec_())