from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

def generate_key_pair():
    """Generate a new RSA key pair and return both the private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serialize a public key and return the bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    """Serialize a private key and return the bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_public_key(filename):
    """Load a public key from a PEM-encoded file and return the key object."""
    with open(filename, "rb") as key_file:
        key_bytes = key_file.read()
    return load_pem_public_key(key_bytes)

def load_private_key(filename):
    """Load a private key from a PEM-encoded file and return the key object."""
    with open(filename, "rb") as key_file:
        key_bytes = key_file.read()
    return load_pem_private_key(key_bytes, None)

def encrypt_message(message, public_key):
    """Encrypt a message using a public key and return the encrypted bytes."""
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_message(encrypted_message, private_key):
    """Decrypt an encrypted message using a private key and return the decrypted message."""
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

