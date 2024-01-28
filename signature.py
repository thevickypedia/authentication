import hashlib
import secrets
import time


def encode_auth_header(username: str, password: str) -> str:
    """Function to encode username and password into an auth header.

    :param username: Username.
    :param password: Password.
    :return: Encoded header.
    """
    timestamp = str(int(time.time()))
    return f"PYS username={username},Signature={hashlib.sha512(bytes(username + password + timestamp, 'utf-8')).hexdigest()},timestamp={timestamp}"


def decode_auth_header(auth_header: str, password: str) -> bool:
    """Decodes the authentication signature.

    :param auth_header: Encoded value from the 'encode_auth_header' function or JavaScript.
    :param password: Original password to re-create the hash for authentication.
    """
    # Split the auth header into individual components
    components = auth_header.split(',')
    username = components[0].split('=')[1]
    signature = components[1].split('=')[1]
    timestamp = components[2].split('=')[1]
    # Recreate the original message
    message = f"{username}{password}{timestamp}"
    # Calculate the expected signature
    expected_signature = hashlib.sha512(bytes(message, "utf-8")).hexdigest()
    # Verify the signature
    if secrets.compare_digest(signature, expected_signature):
        return True
    else:
        return False
