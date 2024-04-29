import os
import random
import sys

from PIL import Image
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QSizePolicy, QLineEdit, QTextEdit
from PyQt5.QtGui import QPixmap

import AES
import DES


class ImageEncryptor(QWidget):
    """A class to represent an image encryptor widget."""

    def __init__(self):
        """Initialize the widget."""
        super().__init__()

        self.setup = False
        self.initUI()

    def initUI(self):
            """Initialize the user interface."""
            if not self.setup:
                self.layout = QVBoxLayout()
                self.layout.setContentsMargins(10, 10, 10, 10)  # Add margins
                self.setLayout(self.layout)
                self.setup = True

            self.aesButton = QPushButton('AES Encryption')
            self.aesButton.clicked.connect(self.aesStart)
            self.aesButton.setStyleSheet("font-size: 20px")
            self.layout.addWidget(self.aesButton)

            self.desButton = QPushButton('DES Encryption')
            self.desButton.clicked.connect(self.desEncryption)
            self.desButton.setStyleSheet("font-size: 20px")
            self.layout.addWidget(self.desButton)
            
            self.uploadButton = QPushButton('Upload Image')
            self.uploadButton.clicked.connect(self.uploadImage)
            self.uploadButton.hide()
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
            
            self.textBox = QLineEdit()
            self.textBox.hide()
            self.layout.addWidget(self.textBox)
            self.textBox.setStyleSheet("font-size: 20px")

            self.encryptTextButton = QPushButton('Encrypt Text')
            self.encryptTextButton.clicked.connect(self.encryptText)
            self.encryptTextButton.hide()
            self.layout.addWidget(self.encryptTextButton)
            self.encryptTextButton.setStyleSheet("font-size: 20px")
            
            self.decryptTextButton = QPushButton('Decrypt Text')
            self.decryptTextButton.clicked.connect(self.decryptText)
            self.decryptTextButton.hide()
            self.layout.addWidget(self.decryptTextButton)
            self.decryptTextButton.setStyleSheet("font-size: 20px")
            
            self.outputTextBox = QTextEdit()
            self.outputTextBox.setReadOnly(True)
            self.outputTextBox.hide()
            self.layout.addWidget(self.outputTextBox)
            self.outputTextBox.setStyleSheet("font-size: 20px")

            self.returnButton = QPushButton('Return')
            self.returnButton.clicked.connect(self.returnToOriginalLayout)
            self.returnButton.setStyleSheet("font-size: 20px")
            self.layout.addWidget(self.returnButton)    

    def returnToOriginalLayout(self):
        self.layout.removeWidget(self.aesButton)
        self.layout.removeWidget(self.desButton)
        self.aesButton.hide()
        self.desButton.hide()
        self.uploadButton.hide() 
        self.encryptButton.hide() 
        self.nextButton.hide() 
        self.imageLabel.clear() 
        self.recoveredImageLabel.hide() 
        self.textBox.hide() 
        self.encryptTextButton.hide() 
        self.decryptTextButton.hide() 
        self.outputTextBox.hide() 
        self.returnButton.hide()
        self.initUI()

    def aesStart(self):
        self.aesButton.hide()
        self.desButton.hide()
        self.uploadButton.show()
        
    def desEncryption(self):
        print('DES Encryption')
        self.aesButton.hide()
        self.desButton.hide()
        self.textBox.show()
        self.encryptTextButton.show()
        
    def encryptText(self):
        """Encrypt the text from the text box."""
        plaintext = self.textBox.text()
        key_str = 'key!'
        self.key = DES.convert_key_to_bits(key_str)
        self.iv = [random.choice([0, 1]) for _ in range(64)]

        text = DES.convert_string_to_bits(plaintext)
        text = DES.pad_bits(text)
        self.encrypted = DES.des_cbc_enc(self.iv, self.key, text)
        encrypted_text = DES.encrypted_to_string(self.encrypted)

        self.decryptTextButton.show()
        self.outputTextBox.show()
        self.outputTextBox.setText("Text Encrypted: " + encrypted_text)
        # Perform the encryption here
        #encrypted_text = encryptedText  # Replace this with actual encryption

    def decryptText(self):
        decrypted = DES.des_cbc_dec(self.iv, self.key, self.encrypted)
        decrypted_text = DES.bytes_to_string(decrypted)
        self.outputTextBox.show()
        self.outputTextBox.setText("Text Decrypted: " + decrypted_text)
        pass

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