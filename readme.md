# Image Encryptor: Image Encryption with AES-128 and Visualized

![image](https://github.com/user-attachments/assets/622af1f3-3c4e-43b8-935f-7db1980f3f80)

## Overview
The Image Encryptor application provides a user-friendly graphical interface for encrypting and decrypting text and images using AES and DES encryption algorithms. This tool demonstrates encryption principles and their practical applications, ensuring the integrity and confidentiality of sensitive data.

## Features
- **AES Image Encryption**: Encrypt and decrypt images securely using the AES encryption algorithm.
- **DES Text Encryption**: Encrypt and decrypt text messages using the DES encryption algorithm.
- **Image Uploading**: Upload images directly through the interface for encryption.
- **Dynamic User Interface**: Adaptive interface with buttons and options that appear based on the selected operation.
- **Preview Results**: View encrypted and decrypted images directly within the application.
- **Text Output**: Display encrypted and decrypted text results.

## Prerequisites
- Python 3.x
- Required libraries:
  - `Pillow` for image processing
  - `PyQt5` for the graphical user interface
  - Custom `AES` and `DES` modules for encryption logic

Install the required libraries using pip:
```bash
pip install pillow pyqt5
```

## How to Run
1. Clone the repository or download the source code.
2. Ensure the `AES` and `DES` modules are located in the same directory as the script.
3. Run the application:
   ```bash
   python <script_name>.py
   ```
4. Interact with the graphical interface to upload images or enter text for encryption.

## User Interface Guide
### Main Menu
- **AES Encryption**: Start the AES encryption workflow for images.
- **DES Encryption**: Start the DES encryption workflow for text.
- **Return**: Reset the interface to the main menu.

### AES Encryption Workflow
1. Click **AES Encryption**.
2. Upload an image using the **Upload Image** button.
3. Click **Encrypt and Decrypt Image** to process the image.
4. View the encrypted image, and proceed to the decrypted image using the **Next** button.

### DES Encryption Workflow
1. Click **DES Encryption**.
2. Enter text in the provided input box.
3. Click **Encrypt Text** to encrypt the text.
4. View the encrypted result.
5. Click **Decrypt Text** to decrypt the encrypted text.

## File Generation
- Encrypted images are saved with a filename pattern: `<original_name>_<random_digits>_encrypted.png`.
- Decrypted images are saved as `<original_name>_<random_digits>_recovered.png`.

## Encryption Details
### AES (Advanced Encryption Standard)
- Mode: CBC (Cipher Block Chaining)
- Key: 128-bit (hardcoded in the example)
- IV: Initialization Vector (hardcoded in the example)

### DES (Data Encryption Standard)
- Mode: CBC
- Key: Derived from a predefined string
- IV: Randomly generated for each session

## Example Usage
### Encrypting and Decrypting an Image
1. Select **AES Encryption**.
2. Upload an image file.
3. Click **Encrypt and Decrypt Image** to process the file.
4. View the intermediate and final results through the interface.

### Encrypting and Decrypting Text
1. Select **DES Encryption**.
2. Enter your text input.
3. Click **Encrypt Text** to see the encrypted output.
4. Click **Decrypt Text** to retrieve the original input.

## Notes
- Ensure that the custom `AES` and `DES` modules are implemented correctly with the required methods.
- This application is for demonstration purposes and may not be suitable for production use without further security considerations.

## License
This project is licensed under the MIT License. Feel free to use and modify the code.

## Contact
For issues or contributions, please contact the author at [your-email@example.com].

