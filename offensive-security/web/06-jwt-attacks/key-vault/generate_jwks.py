from jwcrypto import jwk
import json

key = jwk.JWK.from_pem(open("public.pem","rb").read())
key_dict = json.loads(key.export_public())

key_dict["kid"] = "052954d043c467a6"
key_dict["alg"] = "RS256"
key_dict["use"] = "sig"

jwks = {"keys":[key_dict]}

with open("jwks.json","w") as f:
    json.dump(jwks, f)

print("jwks.json created")
