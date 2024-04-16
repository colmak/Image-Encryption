from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtCore import Qt, QBuffer
import sys
from PIL import Image
import io
import numpy as np
import secrets

# My module
import AES


class ImageEncryptor(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('Image Encryptor')
        self.setGeometry(100, 100, 800, 600)  # Set default size to 800x600

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.uploadButton = QPushButton('Upload Image')
        self.uploadButton.clicked.connect(self.uploadImage)
        self.layout.addWidget(self.uploadButton)

        self.encryptButton = QPushButton('Encrypt Image')
        self.encryptButton.clicked.connect(self.encryptImage)  # Connect to the encryption function
        self.encryptButton.hide()  # Initially hidden
        self.layout.addWidget(self.encryptButton)

        self.decryptButton = QPushButton('Decrypt Image')
        self.decryptButton.clicked.connect(self.decryptImage)  # Connect to the decryption function
        self.decryptButton.hide()  # Initially hidden
        self.layout.addWidget(self.decryptButton)

        self.imageLabel = QLabel()
        self.layout.addWidget(self.imageLabel)

    def uploadImage(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        fileName, _ = QFileDialog.getOpenFileName(self, "QFileDialog.getOpenFileName()", "", "All Files (*);;Python Files (*.py)", options=options)
        if fileName:
            pixmap = QPixmap(fileName)
            self.imageLabel.setPixmap(pixmap)
            self.encryptButton.show()  
            self.decryptButton.show()  
            self.uploadButton.hide()  

    def encryptImage(self):
        # Get the current image
        pixmap = self.imageLabel.pixmap()
        if pixmap is None:
            return

        # Convert the QPixmap to a PIL Image
        buffer = QBuffer()
        buffer.open(QBuffer.ReadWrite)
        pixmap.save(buffer, "PNG")
        pil_im = Image.open(io.BytesIO(buffer.data()))

        # Convert the PIL Image to a byte array
        byte_array = np.array(pil_im)

        # Define a key for the encryption
        key = secrets.token_bytes(16)

        # Apply the AES encryption
        encrypted_byte_array = AES.encrypt(byte_array, key)

        # Convert the encrypted byte array back to a QPixmap
        encrypted_pixmap = QPixmap.fromImage(QImage(encrypted_byte_array.data, encrypted_byte_array.shape[1], encrypted_byte_array.shape[0], QImage.Format_RGB888))

        # Update the image label
        self.imageLabel.setPixmap(encrypted_pixmap)

    def decryptImage(self):
        # Implement the image decryption functionality here
        pass

if __name__ == '__main__':

    app = QApplication(sys.argv)

    window = ImageEncryptor()
    window.show()

    sys.exit(app.exec_())