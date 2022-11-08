import socket
from io import BytesIO
from bitcoin.block import GENESIS_BLOCK, LOWEST_BITS, GENESIS_BLOCKS, Block
from bitcoin.network import BLOCK_DATA_TYPE, GetDataMessage, GetHeadersMessage, HeadersMessage, NetworkEnvelope, SimpleNode, VerAckMessage, VersionMessage
from bitcoin.script import Script, p2pkh_script
from ecc.ecc import FieldElement, Point, PrivateKey, S256Point, Signature 
from bitcoin.core import Tx, TxIn, TxOut
from utils.utils import SIGHASH_ALL, TWO_WEEKS, calculate_new_bits, decode_base58, encode_base58, encode_base58_checksum, hash160, hash256, little_endian_to_int, merkle_parent_level, merkle_root

a = FieldElement(7,  13)

p = Point(-1,-1,5,7)

a = FieldElement(num=0, prime=223)
b = FieldElement(num=7, prime=223)
x = FieldElement(num=192, prime=223)
y = FieldElement(num=105, prime=223)

p1 = Point(x,y,a,b)

print(p1)

a = FieldElement(num=0, prime=223)
b = FieldElement(num=7, prime=223)
x = FieldElement(num=47, prime=223)
y = FieldElement(num=71, prime=223)
p2 = Point(x,y,a,b)

print(2*p2)

# bitcoin curve
# g is called the generator for the curve
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
p = 2**256 - 2**32 - 977
print(gy**2 % p == (gx**3 + 7) % p)

G = S256Point(
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

from ecc.ecc import G, N

print(N*G)

z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6 
s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec 
px = 0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574 
py = 0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4

point = S256Point(px, py)
s_inv = pow(s, N-2, N)
u = z * s_inv % N
v = r * s_inv % N
u_g = u*G
v_p = v*point
print(u_g)
print(v_p)
# print((u*G + v*point).x.num == r)
print( (u_g + v_p).x.num == r )

der = bytes.fromhex('304402201f62993ee03fca342fcb45929993fa6ee885e00ddad8de154f268d98f083991402201e1ca12ad140c04e0e022c38f7ce31da426b8009d02832f0b44f39a6b178b7a1')
sec = bytes.fromhex('0204519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574')
# message is the hash256 of the message "ECDSA is awesome!"
z = int.from_bytes(hash256(b'ECDSA is awesome!'), 'big')
# parse the der format to get the signature
sig = Signature.parse(der)
# parse the sec format to get the public key
point = S256Point.parse(sec)
# use the verify method on S256Point to validate the signature
print(point.verify(z, sig))

# Signging secret
e = int.from_bytes(hash256(b'my secret'), 'big')

# sig hash, ot the message hash we wil be signing
z = int.from_bytes(hash256(b'my message'), 'big')

# fixed k value
k = 1234567890

# kG = (r,y), take x coord only
r = (k*G).x.num
k_inv = pow(k, N-2, N)

# s = (z+re)/k mod N because cyclical group order N
s = (z+r*e) * k_inv % N

# Public points needs to be known by the verifier
point = (e*G)
print(point)


h = '7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d'

print(encode_base58(bytes.fromhex(h)))

priv = PrivateKey(5002)
print(priv.point.address(compressed=False, testnet=True))

priv = PrivateKey(0x12345deadbeef)
print(priv.point.x.num)
print(priv.point.y.num)
print(priv.point.address(compressed=False, testnet=True))

print(priv.point.sec(compressed=True).hex())
priv = PrivateKey(2020**5)
print(priv.point.sec(compressed=True).hex())

priv = PrivateKey(0x12345deadbeef)
print(priv.point.sec(compressed=True).hex())

priv = PrivateKey(5003)
print(priv.wif(compressed=True, testnet=True))

sig = Signature(
    r=0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6,
    s=0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
)

der = sig.der()

print(der.hex())

# chapter 5

hex_transaction = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e\
148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd\
205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4e\
a13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253\
dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd\
3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1c\
dc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a716012\
1035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567\
bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a4730440\
2204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08\
bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0\
172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375\
925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea\
0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23\
852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff272\
2eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1a\
b6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80\
df2b3eda8db57397088ac46430600'

stream = BytesIO(bytes.fromhex(hex_transaction))

tx_obj = Tx.parse(stream)

# print the second tx script sig (e.g 1)
print(tx_obj.tx_ins[1].script_sig)
print(tx_obj.tx_outs[0].script_pubkey)


script_hex = ('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccf\
cf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8\
e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278\
a')

stream = BytesIO(bytes.fromhex(script_hex))

script_sig = Script.parse(stream)
print(script_sig)


original_bytes = bytes.fromhex(script_hex)
serialized_script = script_sig.serialize()

if original_bytes != serialized_script:
    print("seralization has failed")

# z = signature hash
z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d

# sec = public key (compressed or otherwise)
sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
# signature
sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')

# pass in the SEC formatted public key
# this is followed by the opcode for doing
# OP_CHECKSIG (172)
script_pubkey = Script([sec, 0xac])

# create the sig script object
script_sig = Script([sig])

# create the compbined script which should be
# sig
# pubKey
# OP_CHECKSIG
combined_script = script_sig + script_pubkey
print(combined_script.evaluate(z))


script_pubkey = Script([0x76,0x76,0x95,0x93,0x56,0x87])
script_sig = Script([0x52])
combined_script = script_pubkey + script_sig
print(combined_script)
"""
Combined script

SIG         
OP_DUP      
OP_DUP      
OP_MUL      
OP_ADD
OP_6
OP_EQUAL

6 = S^2+S
~ S=2
"""

script_pubkey = Script( [0x6e, 0x87, 0x91, 0xa7, 0x7c, 0xa7, 0x87] )
c1 = '255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f576964746820\
32203020522f4865696768742033203020522f547970652034203020522f537562747970652035\
203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e67\
74682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8\
fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1ff\
fe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db169\
0901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc\
942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a215664613097\
89606bd0bf3f98cda8044629a1'
c2 = '255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f576964746820\
32203020522f4865696768742033203020522f547970652034203020522f537562747970652035\
203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e67\
74682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8\
fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1ff\
fe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a9\
0901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0\
a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd3097\
91d06bd0af3f98cda4bc4629b1'

collision1 = bytes.fromhex(c1)
collision2 = bytes.fromhex(c2)

script_sig = Script( [ collision1, collision2 ] )
combined_script = script_pubkey + script_sig

print(combined_script)
print(combined_script.evaluate(0))

raw_tx = ('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf830\
3c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccf\
cf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8\
e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278\
afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88a\
c99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')

stream = BytesIO(bytes.fromhex(raw_tx))
transaction = Tx.parse(stream)

# validate a signature
sec = bytes.fromhex(
    '0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
)

der = bytes.fromhex(
    '3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed'
)

# Z is the signature hash
z = 0x27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6

pub_key = S256Point.parse(sec)
sig = Signature.parse(der)
print(pub_key.verify(z, sig))

# prints true because the signature is valid

modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914\
bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896\
bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02\
e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288a\
c1943060001000000')

h256 = hash256(modified_tx)

# z = signature hash
z = int.from_bytes(h256, 'big')
print(hex(z))


# 
sec = bytes.fromhex('0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e\
213bf016b278a')
der = bytes.fromhex('3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031c\
cfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9\
c8e10615bed')

pub_key_point = S256Point.parse(sec)
sig = Signature.parse(der)
print(pub_key_point.verify(z, sig))

#
# Creating transactions
#

# transaction hash
prev_tx = bytes.fromhex('0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6\
eb20a080843a299')

# input index to reference
prev_index = 13

# create a TxIn object referening the transaction and the input index
tx_in = TxIn( prev_tx, prev_index )

# empty set for tx_outs to start
tx_outs = []

# amount of change in satoshis
change_amount = int(0.33*100000000)

# get the change address for creating the p2pkh script 
change_h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')

# this is the script for the change
change_script = p2pkh_script(change_h160)

# Create an output for the change amount  
change_output = TxOut(amount=change_amount, script_pubkey=change_script)
res = ''.join(format(x, '02x') for x in change_script.cmds[2])
print(res)

# set the target amount - the BTC we are actually spending
target_amount = int(0.1 * 100000000)

# get the script hash for the target address
target_h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')

print(target_h160)

# get the p2pkh value
target_script = p2pkh_script(target_h160)

# create the output for the p2pkh
target_output = TxOut(amount=target_amount, script_pubkey=target_script)

# create a transaction from the constiutent parts
# and send it to testnet
tx_obj = Tx(1, [tx_in], [change_output, target_output], 0, True)

res = ''.join(format(x, '02x') for x in tx_obj.serialize())

print(res)
print(tx_obj)

#
# Signing the transaction
#

# sign the first input, (only 1), would need to do a for loop for all the other
# inputs if we had multiple ones we owned (with possible different privkeys)
# so we get the hash of the 0th (first) input as our Z in this case
z = tx_obj.sig_hash(0)

# create the private key object with the secret used to dervive the key
private_key = PrivateKey(secret=8675309)


print(hex(z))


# get the der sig
_sig = private_key.sign(z)
print(hex(z))
der = private_key.sign(z).der()

# set the signature portion of the tx 
sig = der + SIGHASH_ALL.to_bytes(1,'big')
res = ''.join(format(x, '02x') for x in sig)
print(res)
# get the public key
sec = private_key.point.sec()

# get the script signature, has only 2 elements in the script
# the signature to match to the script and the public key required
script_sig = Script([sig, sec])

# set the computed script sig to the tx in to prove that we can we
# own the BTC and thus can spend it on this transaction. Only doing this
# for the first input (because we only have 1 input to this tx)
tx_obj.tx_ins[0].script_sig = script_sig

print(tx_obj.serialize().hex())


#
# P2SH address calculation (mainnet)
#

# hash of the redeem script
h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')

# prepend 0x05 for mainnet address
print(encode_base58_checksum(b'\x05' + h160))

hex_redeem_script = '5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
redeem_script = bytes.fromhex(hex_redeem_script)
h160 = hash160(redeem_script)
print(h160.hex())

#
# p2sh signature validation
#
  
# create a modified tx
modified_tx = bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a38\
5aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036\
b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98be\
c453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa0\
5de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b9\
5abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2\
788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c5687000000000\
1000000')

# take the sha256 to get the z value which is the signature hash 
s256 = hash256(modified_tx)

# get z (signature hash) as bytes in big endian format
z = int.from_bytes(s256, 'big')
print(hex(z))

# get the public keys from the tx
sec = bytes.fromhex('022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff\
1295d21cfdb70')

# get the signatures from the tx
der = bytes.fromhex('3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a\
8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4\
ee942a89937')

res = ''.join(format(x, '02x') for x in sec)
print(res)
res = ''.join(format(x, '02x') for x in der)
print(res)

# validate the public key by getting the point on the curve the public key represents
point = S256Point.parse(sec)

print(point.a)
print(point.b)
print(point.x)
print(point.y)

# validate the signature by parsing it to a signature object
sig = Signature.parse(der)

print(hex(sig.r))
print(hex(sig.s))

# verify that for the z (signature hash) 
print(point.verify(z,sig))




#
# Parse the gensis block
#
stream = BytesIO(bytes.fromhex('4d04ffff001d0104455468652054696d6573203033\
2f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64\
206261696c6f757420666f722062616e6b73'))

s = Script.parse(stream)
print(s.cmds[2])

#
# print the block height which is the first byte of the ScriptSig field
#   it is stored little endian
#
stream = BytesIO(bytes.fromhex('5e03d71b07254d696e656420627920416e74506f6f\
6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d94028\
24ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00'))
script_sig = Script.parse(stream)
print(little_endian_to_int(script_sig.cmds[0]))

#
# Block headers
#
block_hash = hash256(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7\
c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c\
3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'))[::-1]
block_id = block_hash.hex()
print(block_id)

#
# Block version
#
b = Block.parse(BytesIO(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b\
4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3\
f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')))

# compare only the upper 3 bits by shifting 0's in and out the lower 29
# bits and compare against 001 for BIP 9
print("BIP9: {}".format(b.version >> 29 == 0b001))

# shift 4 bits and check that the right most bit is 1
print("BIP91: {}".format(b.version >> 4 & 1 == 1))

# this bip is assigned bit 1
print("BIP141: {}".format(b.version >> 1 & 1 == 1))

#
# proof of work example
#
block_id = hash256(bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c5\
3b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c31\
57f961db38fd8b25be1e77a759e93c0118a4ffd71d'))[::-1]

# print as 64 byte hex string (zfill to fill out 64 bytes)
print("{}".format(block_id.hex().zfill(64)))


#
# calculating the proof of work target
# 
bits = bytes.fromhex('e93c0118')
exponent = bits[-1]
coefficient = little_endian_to_int(bits[:-1])

_target = 256 ** (exponent-3)
coef_times_255 = _target * coefficient

target = coefficient * 256 ** (exponent - 3)
print(target)
print("{:x}".format(target).zfill(64))


proof = little_endian_to_int(hash256(bytes.fromhex('020000208ec39428b17323\
fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d3957\
6821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')))
print(proof < target)

difficulty = 0xffff * 256 ** (0x1d-3) / target
print(difficulty)

#
# Calculating the block difficulty target
# 
last_block = Block.parse(BytesIO(bytes.fromhex('00000020fdf740b0e49cf75bb3\
d5168fb3586f7613dcc5cd89675b0100000000000000002e37b144c0baced07eb7e7b64da916cd\
3121f2427005551aeb0ec6a6402ac7d7f0e4235954d801187f5da9f5')))

first_block = Block.parse(BytesIO(bytes.fromhex('000000201ecd89664fd205a37\
566e694269ed76e425803003628ab010000000000000000bfcade29d080d9aae8fd461254b0418\
05ae442749f2a40100440fc0e3d5868e55019345954d80118a1721b2e')))

time_differential = last_block.timestamp - first_block.timestamp

# make sure it took more that 8 weeks to find the last 2015 blocks
# decrease the difficulty
if time_differential > TWO_WEEKS * 4:
    time_differential = TWO_WEEKS * 4

# check if it took less than 3.5 days to find the last 2015 blocks
# increase the difficulty
if time_differential < TWO_WEEKS // 4:
    time_differential = TWO_WEEKS // 4

new_target = last_block.target() * time_differential // TWO_WEEKS
print("{:x}".format(new_target).zfill(64))

# test target function
block_raw = bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')
stream = BytesIO(block_raw)
block = Block.parse(stream)
if block.target() != 0x13ce9000000000000000000000000000000000000000000 :
    print('test failed')




#
# Parsing network traffic
#
msg_hex='f9beb4d976657261636b000000000000000000005df6e0e2'
stream = BytesIO(bytes.fromhex(msg_hex))
envelope = NetworkEnvelope.parse(stream)
msg_serialized = envelope.serialize()
print(envelope.command)
print(envelope.payload)

# hardcoded testnet peer being usesd right now
host = "testnet.programmingbitcoin.com"
port = 18333
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((host,port))

# create a stream to be able to be read from the socket. This stream
# can and will be passed to the parse message
stream = socket.makefile('rb', None)

# first step of the handshake is exchanging version messages
version = VersionMessage(
    receiver_port=18333,
    sender_port=18333,
)

# Place the message into the network envelope
envelope = NetworkEnvelope(
    version.command, 
    version.serialize(),
    testnet=True
)

# Send the message to the peer
socket.sendall(envelope.serialize())

# read the version information from the third party
new_message = NetworkEnvelope.parse(stream, testnet=True)
print(new_message)

# read the verack message off the wire
new_message = NetworkEnvelope.parse(stream, testnet=True)
print(new_message)


node = SimpleNode(
    'testnet.programmingbitcoin.com',
    network='testnet',
    port = 18333
)

# create initial version message to send 
version = VersionMessage()

# send the initial version message to the remote peer
node.send(version)

verack_received = False
version_received = False

while not verack_received and not version_received:
    message = node.wait_for(VersionMessage, VerAckMessage)

    if message.command == VerAckMessage.command:
        verack_received = True
    else:
        version_received = True
        node.send(VerAckMessage())


# create a node
node = SimpleNode(
    'testnet.programmingbitcoin.com',
    network='testnet',
    port = 18333
)

# handshake onto the network
node.handshake()

# start processign from the gensis block
genesis = Block.parse(BytesIO(GENESIS_BLOCK))

# create the get headers message
getheaders = GetHeadersMessage(start_block=genesis.hash())

# finally get headers, should be the first 20000 after the genesis block
node.send(getheaders)

# get some headers
previous = GENESIS_BLOCKS['testnet']
first_epoch_timestamp = previous.timestamp
expected_bits = LOWEST_BITS
count = 1

# create a node
node = SimpleNode(
    'testnet.programmingbitcoin.com',
    network='testnet',
    port = 18333
)

# handshake onto the network
node.handshake()

# get the first 20 blocks
for _ in range(19):
    
    # create the get headers message with the start block being
    # the last parsed block
    getheaders = GetHeadersMessage(start_block=previous.hash())

    # get the response on the network
    node.send(getheaders)

    # now block waiting on HeadMessages from the peer
    headers = node.wait_for(HeadersMessage)

    for header in headers.headers:
        # check that the block header is valid for 
        # the block based on the provided proof of work
        if not header.check_pow():
            raise RuntimeError('bad PoW at block {}'.format(count))

        # check for continuity in the block chain
        prev_hash = previous.hash()
        res = ''.join(format(x, '02x') for x in prev_hash)
        print(str(count) + ": " + res)

        if header.prev_block != prev_hash:
            raise RuntimeError('discontinuous block at {}'.format(count))

        # calculate new bits, This is when the difficulty is adjusted
        if count % 2016 == 0:
            time_diff = previous.timestamp - first_epoch_timestamp
            expected_bits = calculate_new_bits(previous_bits=previous.bits, time_differential=time_diff)
            first_epoch_timestamp = header.timestamp
            res = ''.join(format(x, '02x') for x in expected_bits)
            print(res)
        if header.bits != expected_bits:
            res = ''.join(format(x, '02x') for x in expected_bits)
            print(res)
            res = ''.join(format(x, '02x') for x in header.bits)
            print(res)
            # raise RuntimeError('bad bits at block {}'.format(count))
            print('bad bits at block {}'.format(count))
        previous = header
        count += 1


print("here we go")

#
# Download the first 40 blocks of the blockchain
#
# net = "testnet"
# node = SimpleNode('testnet.programmingbitcoin.com', network=net)

# # connect the node
# node.handshake()

# # set the last block hash to the GENESIS_BLOCKS[net]
# last_block = GENESIS_BLOCKS[net]

# # set the first block of the epoch to the genesis block
# epock_start_block = GENESIS_BLOCKS[net]

# # startging with the first block of the epoch
# current_height = 1

# # loop for 40k blocks
# while current_height < 40000:
    
#     # create a getheadersmessage starting from rthe last block we have
#     getheaders = GetHeadersMessage(start_block=last_block.hash())

#     # send a getheaders message to the network
#     node.send(getheaders)

#     # get the headers from the network
#     headers = node.wait_for(HeadersMessage)

#     # loop through the headers from the headers message
#     for header in headers:

#         # check the proof of work
#         if not header.check_pow():
#             raise RuntimeError(f'bad proof of work at block ')

#         # only check if the current hash isn't the first one
#         if last_block != GENESIS_BLOCKS[net]:

#             # the prev_block of the current block should be the last block
#             if header.prev_block != last_block.hash():
#                 raise RuntimeError(f'discontinuous block at ')

#             # when it's a multiple of 2016
#             if current_height % 2016 == 0:

#                 # set the expected bits using the new_bits method using the last block
#                 expected_bits = last_block.new_bits(epoch_start_block)

#                 # check that the bits are what we expect
#                 if header.bits != expected_bits:
#                     raise RuntimeError(f'bits are off {header.bits.hex()} vs {expected_bits.hex()}')

#                 # set the epoch start block to the current one
#                 epoch_start_block = header

#                 # print the current id
#                 print(header.id())

#         # increment the current_height
#         current_height += 1

#         # set the last_block to the current header's hash
#         last_block = header


hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
    '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
    '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
    '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
    '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
]

# bytes.fromhex to get all the hashes in binary
hashes = [bytes.fromhex(h) for h in hex_hashes]

# initialize current level to be the hashes
current_level = hashes

# loop until current_level has only 1 element
while len(current_level) > 1:

    # make the current level the parent level
    current_level = merkle_parent_level(current_level)

# print the root's hex
print(current_level[0].hex())

#
# Calculate the merkle root
#

want = '4297fb95a0168b959d1469410c7527da5d6243d99699e7d041b7f3916ba93301'

tx_hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
    '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
    '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
    '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
    '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
]

# bytes.fromhex and reverse ([::-1]) to get all the hashes in binary
hashes = [bytes.fromhex(h)[::-1] for h in tx_hex_hashes]

# get the merkle root
root = merkle_root(hashes)

# see if the reversed root is the same as the wanted root
print(root[::-1].hex() == want)


block_hex = '0000000000044b01a9440b34f582fe171c7b8642fedd0ebfccf8fdf6a1810900'
block_hash = bytes.fromhex(block_hex)
# connect to testnet.programmingbitcoin.com on testnet
node = SimpleNode('testnet.programmingbitcoin.com', network="testnet")
# handshake
node.handshake()
# create a GetDataMessage
getdata = GetDataMessage()
# request a block with (BLOCK_DATA_TYPE, block_hash)
getdata.add_data(BLOCK_DATA_TYPE, block_hash)
# send the getdata message
node.send(getdata)
# wait for the block message in response (class is Block)
block_obj = node.wait_for(Block)
# check the proof of work
if not block_obj.check_pow():
    raise RuntimeError('bad proof of work')
# validate the tx_hashes
if not block_obj.validate_merkle_root():
    raise RuntimeError('bad merkle root')
# print the merkle root hex
print(block_obj.merkle_root.hex())



#
# Segwit stuff here
#

