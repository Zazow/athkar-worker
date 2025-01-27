from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import json

# Load the private/public key
with open("./public.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Extract modulus (n) and exponent (e)
public_numbers = public_key.public_numbers()
n = public_numbers.n
e = public_numbers.e

# Base64URL-encode n and e
def to_base64url(num):
    return base64.urlsafe_b64encode(num.to_bytes((num.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")

jwk = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "n": to_base64url(n),
    "e": to_base64url(e),
    # Optional: Add "kid" (Key ID) if needed
}

print(json.dumps(jwk, indent=2))