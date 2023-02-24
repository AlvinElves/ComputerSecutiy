import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SymmetricServer(object):
    def __init__(self):
        super().__init__()
        self.backend = default_backend()

    def _get_blocks(self, message, block_size=32):
        assert len(message) % block_size == 0,  "Inconsistent message size, padding not supported"
        n = len(message) // block_size
        for i in range(0, len(message), n):
            yield message[i:i + n]

    def decrypt_aes_ecb(self, key, ciphertext):
        if self._shared_key is not None:
            key = self._shared_key

        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = b''
        for block in self._get_blocks(ciphertext):
            plaintext = plaintext + decryptor.update(block)
        return plaintext + decryptor.finalize()

    def decrypt_aes_ctr(self, key, message):
        if self._shared_key is not None:
            key = self._shared_key

        iv = message[0:16]
        ciphertext = message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def get_encrypted_message(self):
        if not self._shared_key:
            return None

        from os import urandom
        nonce = urandom(16)

        # Message masked to it a surprise!
        message = b'Bch\\]b[\x14VYg]XY\x14fYaU]bg"\x14FcibX\x14h\\Y\x14XYWUm\x14cZ\x14h\\Uh\x14Wc`cggU`\x14KfYW_ \x14VcibX`Ygg\x14UbX\x14VUfY"\x14H\\Y\x14`cbY\x14UbX\x14`YjY`\x14gUbXg\x14ghfYhW\\\x14ZUf\x14UkUm"'
		
        cipher = Cipher(algorithms.AES(self._shared_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes([(b + 12) % 256 for b in message])) + encryptor.finalize()
        return nonce + ciphertext