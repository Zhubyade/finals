import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class AESCipher(object):
    """Class to create the AES standard encryption
    1. Able to encrypt file or text.
    2. Able to decrypt file or text.
    3. Pad and Unpad Text.
    """

    def __init__(self, key: str):
        """Initializes with Encryption Key
        1. Create block size attribute
        2. Key from user Input or default.
        """
        
        self.block_size: int | float = AES.block_size
        self.key: bytes = hashlib.sha256(key.encode()).digest()


    def encrypt(self, plain_text: str) -> str:
        """Text Encrypt function, provides plain text and return encrypted string.
        1. Can Pad plain text
        2. A new Cipher is created
        3. Returns Encrypted text.
        """

        plain_text: str = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")


    def decrypt(self, encrypted_text: str) -> str:
        """Decrypts a given encrypted text.
        1. Get Encrypted text.
        2. Cipher the encrypted text.
        3. Decrypt Text.
        4. Return Un-padded plain Text.
        """

        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text: str = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")

        return self.__unpad(plain_text)

    def __pad(self, plain_text: str) -> str:
        """Creates a padded text from plain text.
        1. Create Padded.
        2. Returns Padded Plain text.
        """

        number_of_bytes_to_pad: int | float = self.block_size - len(plain_text) % self.block_size
        ascii_string: str = chr(number_of_bytes_to_pad)
        padding_str: str = number_of_bytes_to_pad * ascii_string
        padded_plain_text: str = plain_text + padding_str

        return padded_plain_text


    @staticmethod
    def __unpad(plain_text: str) -> str:
        """Static Method of class un pads a padded text.
        1. Text to pad.
        2. Returns Unpadded Value. 
        """

        last_character: str = plain_text[len(plain_text) - 1:]

        return plain_text[:-ord(last_character)]