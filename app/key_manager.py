import uuid
import base64
# handle expire logic in 2.3
from datetime import datetime, timedelta

# RSA key generation function
from cryptography.hazmat.primitives.asymmetric import rsa

#change int to base64url for n and e in JWKS
def int_to_base64url(val: int) -> str:
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("utf-8")

# manage key generation stuff (1) and 2.3 expire logic
class KeyManager:

    # add keys and initialize all keys
    def __init__(self):
        self.keys_list = []
        self.initialize_all_keys()


    # generates RSA private key
    # based off example used here. https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    def make_private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)


    # creates active key and expired key at startup
    def initialize_all_keys(self):
        # current timestamp used for expiration comparison
        now = datetime.now()
        
        #key id = kid
        #private key for signing
        #public key for verifying
        
        #active key
        active_private = self.make_private_key()
        self.keys_list.append({
            "kid": str(uuid.uuid4()),
            "private_key": active_private,
            "public_key": active_private.public_key(),
            # set expiration 1 hour in the future to work
            "expires_at": now + timedelta(hours=1)
        })

        #expired key
        expired_private = self.make_private_key()
        self.keys_list.append({
            "kid": str(uuid.uuid4()),
            "private_key": expired_private,
            "public_key": expired_private.public_key(),
            # set expiration 1 hour in the past to expire
            "expires_at": now - timedelta(hours=1)
        })


    #returns active key
    def get_active_key(self):
        now = datetime.now()
        for key in self.keys_list:
            if key["expires_at"] > now:
                return key
        raise ValueError("No active key found")


    #returns expired key
    def get_expired_key(self):
        now = datetime.now()
        for key in self.keys_list:
            if key["expires_at"] <= now:
                return key
        raise ValueError("No expired key found")


    #returns list JWKS objects
    def get_valid_public_keys(self):
        now = datetime.now()
        jwks_keys = []
        for key in self.keys_list:
            if key["expires_at"] > now:
                numbers = key["public_key"].public_numbers()
                
                jwks_keys.append({
                    "kid": key["kid"],
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": int_to_base64url(numbers.n),
                    "e": int_to_base64url(numbers.e)
                })
        return {"keys": jwks_keys}


key_manager = KeyManager()