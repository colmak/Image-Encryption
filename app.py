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
            self.setWindowTitle('Image Encryptor')
            self.setGeometry(100, 100, 800, 600)

            self.layout = QGridLayout()
            self.layout.setContentsMargins(10, 10, 10, 10)  # Add margins
            self.setLayout(self.layout)

            self.uploadButton = QPushButton('Upload Image')
            self.uploadButton.clicked.connect(self.uploadImage)
            self.uploadButton.setStyleSheet("font-size: 20px")

            # Add spacers on either side of the button
            self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 0)
            self.layout.addWidget(self.uploadButton, 0, 1)
            self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 2)


            self.encryptButton = QPushButton('Encrypt Image')
            self.encryptButton.setIcon(QIcon('encrypt_icon.png'))  # Add icon
            self.encryptButton.clicked.connect(self.encryptImage)
            self.encryptButton.hide()
            self.layout.addWidget(self.encryptButton, 1, 0)  # Position in grid
            self.encryptButton.setStyleSheet("font-size: 20px")

            self.decryptButton = QPushButton('Decrypt Image')
            self.decryptButton.setIcon(QIcon('decrypt_icon.png'))  # Add icon
            self.decryptButton.clicked.connect(self.decryptImage)
            self.decryptButton.hide()
            self.layout.addWidget(self.decryptButton, 2, 0)  # Position in grid
            self.decryptButton.setStyleSheet("font-size: 20px")

            self.imageLabel = QLabel()
            self.imageLabel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)  # Allow label to expand
            self.layout.addWidget(self.imageLabel, 0, 1, 3, 1)  # Span across rows
            self.imageLabel.setStyleSheet("font-size: 20px")

    def uploadImage(self):
        """Upload an image."""
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
        """Encrypt an image."""
        pass

    def decryptImage(self):
        """Decrypt an image."""
        pass


if __name__ == '__main__':
    app = QApplication(sys.argv)

    window = ImageEncryptor()
    window.show()

    sys.exit(app.exec_())