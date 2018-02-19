import uuid
import hashlib

def hash_password(message):
    message = message.encode('utf-8')
    return hashlib.sha3_256(message).hexdigest()

print(hash_password("hello"))


print("and here the real deal")

bits = 0x18048ed4
exp = bits >> 24  # 0x18
mant = bits & 0xffffff  # 0x48ed4
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
# '0000000000000000048ed4000000000000000000000000000000000000000000'
import hashlib
import struct
import binascii


sha256 = hashlib.sha256


block = (
    struct.pack('<L', 0x20000000) +
    bytes.fromhex('00000000000000000146161cdb757ffc5a8b22dff06b27a76f6f7d0584f5df05')[::-1] +
    bytes.fromhex('536e129807282bf22dcb0c169dc0e5cfeb47dac85c7afde3afb2e0fb02161076')[::-1] +
    struct.pack('<LLL', 0x57ea765e, 0x18048ed4, 0x9bb0a8f6)
)


first_hash = sha256(block).digest()
second_hash = sha256(first_hash).digest()


print(binascii.b2a_hex(block))
print(binascii.b2a_hex(first_hash[::-1]))
print(binascii.b2a_hex(second_hash[::-1]))
