# based on https://gist.github.com/turunut/7857bd34bac37a04a91a91ee9ea33520
# and https://gist.github.com/shirriff/cd5c66da6ba21a96bb26


import hashlib, struct, codecs
import binascii
import datetime
import time

#2018-02-18 02:42:46
#dt = datetime.datetime(2018, 2, 18, 2, 42, 46)
#time_ = hex(int(time.mktime(dt.timetuple())))
#print("time: " + str(time_))

#get block header declarations

ver = 2
prev_block = "0000000000000000004661b9f832c5f4d9f7d509b5f2a2b65f3b826d7824fb27"
mrkl_root = "3c30b1840b1e6483edde72fea7694562375cdf4ecbb96fee6531959dbbf94499"
time_ = 0x5a892e76
bits = 0x1761e9f8

#calculate difficulty / determines target value

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
# real target
target_str = codecs.decode(target_hexstr, "hex")

# very low target
#target_str = b'\x00\x00a\xe9\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
# low target
#target_str = b'\x00\x00\x00a\xe9\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# start mining / brute force guessing:
# increment nonce, concatenate to previous block header
# hash it with sha256 algorythm
# compare new block header with target value (should be below)

nonce = 0
while nonce < 0x100000000:
    header = ( struct.pack("<L", ver) + codecs.decode(prev_block, "hex")[::-1] +
          codecs.decode(mrkl_root, "hex")[::-1] + struct.pack("<LLL", time_, bits, nonce))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    #print("encrypt with sha256: nonce %s " % nonce, "+ old hash", " = ", "hash: %s" % str(codecs.encode(hash[::-1], "hex"))[1:], " > " "target: %s " % str(binascii.hexlify(target_str))[1:])
    if hash[::-1] < target_str:
        print('* found nonce %s for hash %s' % (nonce, str(codecs.encode(hash[::-1], "hex"))[1:]))
        print('* target %s' % str(binascii.hexlify(target_str))[1:])
        print('* ready for broadcasting block to network')
        break
    nonce += 1
