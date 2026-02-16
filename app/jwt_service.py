import time
import jwt
from cryptography.hazmat.primitives import serialization


class JWTService:
    def __init__(self, key_manager):
        #manager for handling keys
        self.key_manager = key_manager

    def issue_token(self, expired = False):
        #select key
        if expired:
            key = self.key_manager.get_expired_key()
        else:
            key = self.key_manager.get_active_key()
            
        #payload
        payload = {
            "sub": "fake-user",
            "iat": int(time.time()),
            "exp": int(key["expires_at"].timestamp())
        }

        #serialize private key to PEM format
        private_pem = key["private_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        #encode JWT
        token = jwt.encode(
            payload,
            private_pem,
            algorithm="RS256",
            headers={"kid": key["kid"]}
        )

        return token
