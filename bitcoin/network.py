from io import BytesIO
from random import randint
import socket
import time
from bitcoin.block import Block
from utils.utils import encode_varint, hash256, int_to_little_endian, little_endian_to_int, read_varint

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4

MAGIC = {
    "mainnet": b"\xf9\xbe\xb4\xd9",
    "testnet": b"\x0b\x11\x09\x07",
    "signet": b"\x0a\x03\xcf\x40",
}
PORT = {
    "mainnet": 8333,
    "testnet": 18333,
    "signet": 38333,
}

class NetworkEnvelope:
    def __init__(self, command, payload, testnet=False) -> None:
        self.command = command
        self.payload = payload

        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    
    def __repr__(self) -> str:
        return "{}: {}".format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    def stream(self):
        """Returns a stream for parsing the payload"""
        return BytesIO(self.payload)

    
    @classmethod
    def parse(cls, s, testnet=False):

        # first 4 bytes of the stream is the magic bytes
        magic = s.read(4)

        # ensure the stream has data in it
        if magic == b'':
            raise IOError("Connection reset")

        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC

        if magic != expected_magic:
            # indicates a mismatch between what we received on the stream
            # and what was being expected
            raise SyntaxError(
                "Magic is not right {} vs {}".format(
                    magic.hex(),
                    expected_magic.hex(),
                )
            )

        # command is the next 12 bytes
        command = s.read(12)
        command = command.strip(b'\x00')

        # read the payload
        payload_length = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_length)

        calculated_checksum = hash256(payload)[:4]

        # check the checksum supplied matches the calculated version
        if calculated_checksum != checksum:
            raise IOError(
                "checksome does not match {} vs {}".format(
                    checksum,
                    calculated_checksum,
                )
            )
        
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        result = self.magic

        # backfill all remaining space after the command
        # with null bytes
        result += self.command + b'\x00' * (12 - len(self.command))

        # set the size of the payload next
        result += int_to_little_endian(len(self.payload),4)

        res = ''.join(format(x, '02x') for x in result)
        print(res)

        # add in the checksum which is the first 4 bytes of the hash256
        # of the payload
        result += hash256(self.payload)[:4]

        res = ''.join(format(x, '02x') for x in result)
        print(res)

        # finally add in the payload
        result += self.payload

        res = ''.join(format(x, '02x') for x in result)
        print(res)

        return result

class VersionMessage:
    command = b'version'

    def __init__(self,
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b'\x00\x00\x00\x00',
        receiver_port=8333,
        sender_services=0,
        sender_ip=b'\x00\x00\x00\x00',
        sender_port=8333,
        nonce=None,
        user_agent=b'/programmingbitcoin:0.1',
        latest_block=0,
        relay=False) -> None:

        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port= receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0,2**64),8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    @classmethod
    def parse(cls, s):
        return cls

    def serialize(self):
        """Serialize this message to send over the network"""
        
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b"\x00" * 10 + b"\xff\xff" + self.receiver_ip
        
        # receiver port is 2 bytes, little endian
        result += self.receiver_port.to_bytes(2, 'big')
        
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b"\x00" * 10 + b"\xff\xff" + self.sender_ip
        
        # sender port is 2 bytes, big endian
        result += self.sender_port.to_bytes(2, 'big')
        
        # nonce
        result += self.nonce
        
        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        
        result += self.user_agent
        
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b"\x01"
        else:
            result += b"\x00"
        return result

class GetHeadersMessage:
    command = b"getheaders"

    def __init__(self, 
        version=70015,
        num_hashes=1, 
        start_block=None, 
        end_block=None
        ):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError("a start block is required")
        self.start_block = start_block
        if end_block is None:
            self.end_block = b"\x00" * 32
        else:
            self.end_block = end_block

    def serialize(self):
        """Serialize this message to send over the network"""
        
        # protocol version is 4 bytes little-endian
        result = int_to_little_endian(self.version, 4)
        
        # number of hashes is a varint
        result += encode_varint(self.num_hashes)
        
        # start block is in little-endian
        result += self.start_block[::-1]
        
        # end block is also in little-endian
        result += self.end_block[::-1]
        return result  
        
class HeadersMessage:
    command = b"headers"

    def __init__(self, headers):
        self.headers = headers

    def __iter__(self):
        for header in self.headers:
            yield header

    @classmethod
    def parse(cls, s):
        
        # number of headers is in a varint
        num_headers = read_varint(s)
        
        # initialize the headers array
        headers = []
        
        # loop through number of headers times
        for _ in range(num_headers):
        
            # parse a header using Block.parse(s)
            header = Block.parse(s)
        
            # add the header to the headers array
            headers.append(header)

            # read the number of hashes off the wire
            num_txs = read_varint(s)
        
            # check that the length of header.tx_hashes to be 0 or raise a RuntimeError
            if num_txs != 0:
                raise RuntimeError("number of txs not 0")
        
        # return a class instance
        return cls(headers)

class VerAckMessage:
    command = b"verack"

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b""

class PingMessage:
    command = b"ping"

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce

class PongMessage:
    command = b"pong"

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce

class SimpleNode:
    def __init__(self, host, port=None, network="mainnet", logging=False):
        if port is None:
            port = PORT[network]
        self.network = network
        self.logging = logging
        # connect to socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        # create a stream that we can use with the rest of the library
        self.stream = self.socket.makefile("rb", None)

    def handshake(self):
        """Do a handshake with the other node. Handshake is sending a version message and getting a verack back."""

        # create a version message
        version_msg = VersionMessage()

        # send the message
        self.send(version_msg)

        # wait for a verack message
        self.wait_for(VerAckMessage)


    def send(self, message):
        """Send a message to the connected node"""
        # create a network envelope
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=True 
        )
        # if self.logging:
        #     print(f"sending: {envelope}")
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def read(self):
        """Read a message from the socket"""

        if self.network == "testnet":
            testnet=True
        else:
            testnet = False
        envelope = NetworkEnvelope.parse(self.stream, testnet)
        if self.logging:
            print(f"receiving: {envelope}")
        return envelope

    def wait_for(self, *message_classes):
        """Wait for one of the messages in the list"""
        # initialize the command we have, which should be None
        command = None
        command_to_class = {m.command: m for m in message_classes}
        
        # loop until the command is in the commands we want
        while command not in command_to_class.keys():
        
            # get the next network message
            envelope = self.read()
        
            # set the command to be evaluated
            command = envelope.command
        
            # we know how to respond to version and ping, handle that here
            if command == VersionMessage.command:
        
                # send verack
                self.send(VerAckMessage())
            elif command == PingMessage.command:
        
                # send pong
                self.send(PongMessage(envelope.payload))
        
        # return the envelope parsed as a member of the right message class
        return command_to_class[command].parse(envelope.stream())

class GetDataMessage:
    command = b"getdata"

    def __init__(self):
        self.data = []

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))

    def serialize(self):

        # start with the number of items as a varint
        result = encode_varint(len(self.data))

        # loop through self.data which is a list of data_type and identifier
        for data_type, identifier in self.data:

            # data type is 4 bytes little endian
            result += int_to_little_endian(data_type, 4)

            # identifier needs to be in little endian
            result += identifier[::-1]

        # return the whole thing
        return result