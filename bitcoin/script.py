from hashlib import sha256
from io import BytesIO
from logging import getLogger
from unittest import TestCase

from utils.utils import (
    encode_varint,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from bitcoin.op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
    op_equal,
    op_hash160,
    op_verify,
)


LOGGER = getLogger(__name__)

class Script:
    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            # each command is either an opcode to be executed or a data element to be 
            # pushed onto the stack
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other):
        """Append two scripts together into a new script"""
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        # get the length of the entire field
        length = read_varint(s)

        # initialize the cmds array
        cmds = []

        # initialize the number of bytes we've read to 0
        count = 0

        # loop until we've read length bytes
        while count < length:

            # get the current byte
            current = s.read(1)

            # increment the bytes we've read
            count += 1

            # convert the current byte to an integer
            current_byte = current[0]

            # if the current byte is between 1 and 75 inclusive
            # this indicates the byte is an opcode to be parsed
            if current_byte >= 1 and current_byte <= 75:

                # we have an cmd set n to be the current byte
                n = current_byte

                # add the next n bytes as an cmd
                cmds.append(s.read(n))

                # increase the count by n
                count += n

            # op_pushdata1
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1

            # op_pushdata2
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # we have an opcode. set the current byte to op_code
                op_code = current_byte
                
                # add the op_code to the list of cmds
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        # initialize what we'll send back
        result = b''
        
        # go through each cmd
        for cmd in self.cmds:
      
            # if the cmd is an integer, it's an opcode
            if type(cmd) == int:
       
                # turn the cmd into a single byte integer using int_to_little_endian
                result += int_to_little_endian(cmd, 1)
            else:
     
                # otherwise, this is an element
                # get the length in bytes
                length = len(cmd)

                # for large lengths, we have to use a pushdata opcode
                if length < 75:

                    # turn the length into a single byte integer
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:

                    # 76 is pushdata1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:

                    # 77 is pushdata2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def is_p2pkh_script_pubkey(self):
        # check that the 5 commands are there verbatim
        return (
            len(self.commands) == 5
            and self.commands[0] == 0x76
            and self.commands[1] == 0xA9
            and type(self.commands[2]) == bytes
            and len(self.commands[2]) == 20
            and self.commands[3] == 0x88
            and self.commands[4] == 0xAC
        )

    def is_p2sh_script_pubkey(self) -> bool:
        # validate that the correct sequence of
        # instructions were parsed.
        return (
            len(self.commands) == 3
            and self.commands[0] == 0xA9
            and type(self.commands[1]) == bytes
            and len(self.commands[1]) == 20
            and self.commands[2] == 0x87
        )

    def serialize(self):
        # get the raw serialization (no prepended length)
        
        result = self.raw_serialize()
        # get the length of the whole thing
        
        total = len(result)
        
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def evaluate(self, z, witness=None):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                # do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                # add the cmd to the stack
                stack.append(cmd)

                # now we need to handle the p2sh option by inspecting the stack
                # and seeing if the next 3 commands match the p2sh op alignment:
                # Element (Redeem Script)
                # OP_HASH160 (0xa9)
                # Element Hash160(redeem_script) 20 bytes long
                # OP_EQUAL (0x87)

                if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:

                    # we've found the pattern in the op codes to indicate this is
                    # at p2sh.

                    # pop off the OP_HASH160 opcode
                    cmds.pop()

                    # get the h160 value
                    h160 = cmds.pop()

                    # hash the redeem script off the stack
                    if not op_hash160(stack):
                        return False

                    # push the result onto the stack to compare against the
                    # encoded hash in the input
                    stack.append(h160)

                    # execute the OP_EQUAL op code
                    if not op_equal(stack):
                        return False
                    
                    # verify that the hashes matched with op_verify
                    if not op_verify(stack):
                        LOGGER.info("Bad p2sh h160")
                        return False

                    # get encoded (serialized) redeem script 
                    redeem_script = encode_varint(len(cmd)) + cmd

                    # create a byte stream from the redeem script
                    stream = BytesIO(redeem_script)

                    # add the redeem script to the stack to be execute now
                    cmds.extend(Script.parse(stream).cmds)

                # witness program version 0 rule. if stack cmds are:
                # 0 <20 byte hash> this is p2wpkh
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:
                    # get the signature
                    h160 = stack.pop()
                    
                    # pop off the 0 from the stack
                    stack.pop()

                    # add in the witness to the commands which was passed into the function
                    cmds.extend(witness)

                    # generate a p2pkh script from the signature popped off the stack
                    cmds.extend(p2pkh_script(h160).cmds)

                # handle p2sh
                if len(stack) == 2 and stack[0]==b'' and len(stack[1] == 32):
                    # get the sha256 of the witness script
                    s256 = stack.pop()

                    # pop off the 0 from the stack
                    stack.pop()
                    
                    # add everything in the witness field to the program
                    cmds.extend(witness[:-1])

                    # witness script is the last element of the witness field
                    witness_script = witness[-1]

                    # verify the script matches the sig
                    if s256 != sha256(witness_script):
                        print("bad sha256 {} vs {}".format(s256.hex(), sha256(witness_script).hex()))
                        return False
                    
                    stream = BytesIO(encode_varint(len(witness))) + witness_script
                    witness_script_cmds = Script.parse(stream).cmds
                    
                    # now add in the witness program to the command set
                    cmds.extend(witness_script_cmds)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True
        
    def address(self, network="mainnet"):
        """Returns the address corresponding to the script"""
        # if p2pkh
        if self.is_p2pkh_script_pubkey():  # p2pkh
            # hash160 is the 3rd command
            h160 = self.commands[2]
            # convert to p2pkh address using h160_to_p2pkh_address (remember network)
            return h160_to_p2pkh_address(h160, network)
        # if p2sh
        elif self.is_p2sh_script_pubkey():  # p2sh
            # hash160 is the 2nd command
            h160 = self.commands[1]
            # convert to p2sh address using h160_to_p2sh_address (remember network)
            return h160_to_p2sh_address(h160, network)
        # raise a ValueError
        raise ValueError("Unknown ScriptPubKey")

    def p2wpk_script(h160):
        '''take a hash160 and returns the p2wpkh ScriptPubKey'''
        return Script([0x00, h160])

    def is_p2wpkh_script_pubkey(self) -> bool:
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20

    def is_p2wsh_script_pubkey(self) -> bool:
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 32

class ScriptTest(TestCase):

    def test_parse(self):
        script_pubkey = BytesIO(bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
        script = Script.parse(script_pubkey)
        want = bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertEqual(script.cmds[0].hex(), want.hex())
        want = bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertEqual(script.cmds[1], want)

    def test_serialize(self):
        want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)

def p2pkh_script(h160):
    """convert 20 byte hash to a ScriptPubKey
    Converts the hash160 to p2pkh"""

    # 0x76 OP_DUP
    # 0xa9 OP_HASH160
    # var  h160 type byte element
    # 0x88 OP_EQUALVERIFY
    # 0xac OP_CHECKSIG
    # above is the p2pkh command set

    return Script( [0x76, 0xa9, h160, 0x88, 0xac ] )
    
def p2wsh_script(h256):
    '''Takes a hash160 and returns the p2wsh ScriptPubKey''' 
    return Script([0x00, h256])