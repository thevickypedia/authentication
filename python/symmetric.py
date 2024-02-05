from typing import Any

from cryptography.fernet import Fernet


def keygen() -> str:
    """Generate key for fernet encryption.

    :return: Decoded key.
    """
    key = Fernet.generate_key().decode()
    print("Save this key to decrypt")
    print("*" * 120)
    print(" " * 38 + key)
    print("*" * 120)
    return key


def encrypt(key: str, payload: Any) -> str:
    """Encrypt the given payload, with a unique key.

    :param key: Key to encrypt the data.
    :param payload: Data to encrypt.
    :return: Encrypted data.
    """
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(str(payload).encode("utf-8")).decode()


def decrypt(key: str, encrypted: str):
    """Decrypt data using the key, that was used for encryption.

    :param key: Key used for encryption.
    :param encrypted: Encrypted payload.
    :return: Decoded data.
    """
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted).decode()
