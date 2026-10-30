import base64
import hashlib
import sys

access_token = sys.argv[1]
expected = base64.urlsafe_b64encode(
    hashlib.shake_256(access_token.encode("ascii")).digest(64)[:32]
).rstrip(b"=").decode()

print(expected)
