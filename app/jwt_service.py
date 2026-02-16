import time
import jwt
from cryptography.hazmat.primitives import serialization


class JWTService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def issue_token(self, expired: bool = False) -> str:
        # Select key
        key = self.key_manager.get_expired_key() if expired else self.key_manager.get_active_key()

        # Payload
        payload = {
            "sub": "fake-user",
            "iat": int(time.time()),
            "exp": int(key["expires_at"].timestamp())
        }

        # Serialize private key to PEM
        private_pem = key["private_key"].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encode JWT
        token = jwt.encode(
            payload,
            private_pem,
            algorithm="RS256",
            headers={"kid": key["kid"]}
        )

        return token
