from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes 
import base64
def generateKeyFromPasswd(password: str, salt: bytes):
    encryptKey = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt = salt,
            iterations=100000
            )
    return base64.urlsafe_b64encode(encryptKey.derive(password.encode()))
