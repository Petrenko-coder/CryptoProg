import hashlib

with open("hashfile.txt", "rb") as f:
    print(hashlib.sha256(f.read()).hexdigest())
