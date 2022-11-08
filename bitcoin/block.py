
# constants
from io import BytesIO
from os import times
from utils.utils import bits_to_target, hash256, int_to_little_endian, little_endian_to_int


MAX_TARGET = 0xFFFF * 256 ** (0x1D - 3)
TWO_WEEKS = 60 * 60 * 24 * 14

LOWEST_BITS = bytes.fromhex('ffff001d')
GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
TESTNET_GENESIS_BLOCK = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')


class Block:
    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None) -> None:
        # version of the block
        self.version = version

        # pointer back to the previous block which is traceable all the way
        # back to the gensis block
        self.prev_block = prev_block

        # encodes all ordered transactions into a 32 byte hash
        self.merkle_root = merkle_root

        # unix epoch time stamp
        self.timestamp = timestamp

        # proof of work
        self.bits = bits

        # number varied during the proof of work
        self.nonce = nonce


        self.tx_hashes = tx_hashes
        self.merkle_tree = None
    
    @classmethod
    def parse_header(cls, s):
        """Takes a byte stream and parses a block. Returns a Block object"""
        # s.read(n) will read n bytes from the stream
        # version - 4 bytes, little endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # prev_block - 32 bytes, little endian (use [::-1] to reverse)
        prev_block = s.read(32)[::-1]
        # merkle_root - 32 bytes, little endian (use [::-1] to reverse)
        merkle_root = s.read(32)[::-1]
        # timestamp - 4 bytes, little endian, interpret as int
        timestamp = little_endian_to_int(s.read(4))
        # bits - 4 bytes
        bits = s.read(4)
        # nonce - 4 bytes
        nonce = s.read(4)
        # initialize class
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)
   
    @classmethod
    def parse(cls, s):
        """parse a byte stream and return a Block object"""

        # read the version as the first 4 bytes
        version = little_endian_to_int(s.read(4))

        # list[<start>:<stop>:<step>]
        # >>> a = '1234'
        # >>> a[::-1]
        # '4321'
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)

        return cls(
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        )

    def serialize(self):
        # just the inverse of parse
        result = int_to_little_endian(self.version, 4) 

        # reverse bytewise to make it little endian
        # 32 bytes in length
        result += self.prev_block[::-1]

        # reverse bytewise to make it little endian
        # 32 bytes in length
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce

        return result

    def hash(self):
        s = self.serialize()
        sha = hash256(s)
        return sha[::-1]

    def bip9(self) -> bool:
        return self.version >> 29 & 0b001
    
    def bip91(self) -> bool:
        return self.version >> 4 & 1 == 1
    
    def bip141(self) -> bool:
        return self.version >> 1 & 1 == 1

    def target(self):
        return bits_to_target(self.bits)

    def difficulty(self):
         lowest = 0xffff * 256**(0x1d-3)
         return lowest/self.target()

    def check_pow(self):
        """check the proof of work"""
        sha = hash256(self.serialize())
        proof = little_endian_to_int(sha)
        return proof < self.target()


GENESIS_BLOCKS = {
    "mainnet": Block.parse_header(
        BytesIO(
            bytes.fromhex(
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
            )
        )
    ),
    "testnet": Block.parse_header(
        BytesIO(
            bytes.fromhex(
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18"
            )
        )
    ),
    "signet": Block.parse_header(
        BytesIO(
            bytes.fromhex(
                "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203"
            )
        )
    ),
}