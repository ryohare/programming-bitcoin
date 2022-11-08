from io import BytesIO
import json
from bitcoin.script import Script,p2pkh_script
import requests

from utils.utils import SIGHASH_ALL, encode_varint, hash256, int_to_little_endian, little_endian_to_int, read_varint


class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False) -> None:
        self.version = version

        # inputs to the transactions (e.g. output from another transaction)
        self.tx_ins = tx_ins

        # outputs of the transactions
        self.tx_outs = tx_outs

        self.locktime = locktime
        self.testnet = testnet

        # segwit stuff
        self.segwith = segwit
        self._hash_prevouts = None
        self._hash_squence = None
        self._hash_outputs = None

    def __repr__(self) -> str:
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        return self.hash().hex()

    def hash(self):
        """
            Hash256 of of the serialization in little-endian
        """
        return hash256(self.serialize_legacy())[::-1]

    @classmethod
    def parse(cls, s, testnet=False) -> object:
        """Parse a transaction into a transaction class"""
        # determine if this is a segwit transaction. Read the first 4 bytes, which are the version
        # then look at the 5th byte to be 0x00 which is the segwit marker
        s.read(4)

        # check for the segwit marker
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        
        # rewind the stream for downstream processing
        s.seek(-5,1)

        return parse_method(s,testnet=testnet)

    @classmethod
    def parse_segwit(cls, s, testnet=False) -> object:
        """"parses a segwit transaction"""

        # first 4 bytes are the version
        version = little_endian_to_int(s.read(4))

        # next is the segwit markers, and segwit flags
        # both are expected to be 00 and 01
        marker = s.read(2)

        # check the marker is as expected
        if marker != b'\x00\x01':
            raise RuntimeError("not a segwit transaction {}".format(marker))

        # the next bytes are the number of inputs to read off the wire
        # this value is stored as a varint
        num_inputs = read_varint(s)

        # iterate over the inputs, parsing each one into a TxIn class
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))

        # next bytes are the number of outputs as a varint
        num_outputs = read_varint(s)

        # iterate over the outputs, parsing each one into the TxOut class
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
    
        # now we have the witness field which will have witness information for each input
        for tx_in in inputs:

            # first bytes off the wire is a varint which states how many segwit items to parse
            num_items = read_varint(s)

            # iterate over the segwit items and read each one in and assign to the 
            # corresponding txin
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)

                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            
            # assign the witness data to the txin object
            tx_in.witness = items
        
        # finally we have locktime to be parsed off the wire
        locktime = little_endian_to_int(s.read(4))

        # return the instantion of the object
        return cls (
            version,
            inputs,
            outputs,
            locktime,
            testnet=testnet,
            segwit=True,
        )

    @classmethod
    def parse_legacy(cls, s, testnet=False) -> object:
        """"parses a legacy transaction"""

        
        # the first 4 bytes are the version of the transaction
        version = little_endian_to_int(s.read(4))

        # as a varint next are the number of inputs into the transaction
        # this is the number of inputs to read off the byte stream
        num_inputs = read_varint(s)
        inputs = []

        # for the number of inputs, parse each one off the byte stream
        # and store locally
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        
        # now parse the outputs, starting by reading the number of outputs
        # as a varint
        num_outputs = read_varint(s)

        # for the number of outputs, parse each one off the byte stream
        # and store locally
        outputs = []
        for _ in range( num_outputs) :
            outputs.append(TxOut.parse(s))
        
        # next off the wire is the lock time
        locktime = little_endian_to_int(s.read(4))

        # return the instantion of the class
        return cls(
            version,
            inputs,
            outputs,
            locktime,
            testnet=testnet,
            segwit=False
        )

    def sign_input(self, input_index, private_key):
        """Signs the input using the private key"""
        
        # get the sig_hash (z)
        z = self.sig_hash(input_index)
       
        # get der signature of z from private key
        # der encoding of signing by the of the input 
        # with the t
        der = private_key.sign(z).der()
      
        # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
     
        # calculate the sec
        sec = private_key.point.sec()

        # combine the scripts into one script_sig object
        # initialize a new script with [sig, sec] as the elements
        script_sig = Script([sig, sec])
   
        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script_sig
        
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def serialize_legacy(self) -> bytes:
        """returns the byte serialization of the transaction"""

        # set the transaction version
        result = int_to_little_endian(self.version, 4)

        # encode the number of input transactions
        result += encode_varint(len(self.tx_ins))

        # serialize each input transaction
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        
        # encode the number of output transactions
        result += encode_varint(len(self.tx_outs))
        
        # serialize each outut transaction
        for tx_out in self.tx_outs:
            result += tx_out.serialize()

        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)

        # final result is a fully serialized transaction
        return result

    def serialize_segwit(self):
        # first 4 bytes are the version
        result = int_to_little_endian(self.version, 4)

        # next we add the segwit maker
        result += b'\x00\x01'

        # next we encode the number of transactions as a varint
        result += encode_varint(len(self.tx_ins))
        
        # serialize each of the inputs now
        for tx_in in self.tx_ins:
            result += tx_in.serialize()

        # next the outputs, encode the length as a varint
        result += encode_varint(len(self.tx_outs))

        # serialize each of the outputs now
        for tx_out in self.tx_outs:
            result += tx_out.serialize()

        # now we need to add the witness data to the transaction.
        # The witness data is a per input field, so for each input
        # we need to add the witness data to the transaction
        for tx_in in self.tx_ins:
            # first on the wire is the length of the witness data
            # which is to be read. It is written as a single byte?
            result += int_to_little_endian(len(tx_in.witness),1)

            # serialize each witness data item
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little_endian(item,1)
                else:
                    result += encode_varint(len(item))+item
        
        # add the locktime to the result
        result += int_to_little_endian(self.locktime, 4)

        # and were done
        return result

    def serialize(self) -> bytes:
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def fee(self, testnet=False):
        input_sum, output_sum = 0,0

        # sum the inputs to get the input_sum value
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet=testnet)
        
        # sum the outputs to get the output_sum value
        for tx_out in self.tx_outs:
            output_sum += tx_out.value(testnet=testnet)

        # the fee amunt is the difference between the input and output sums
        return input_sum - output_sum

    def sig_hash(self, input_index, redeem_script=None):
        # generate the serialized data to hash for the signature
        # first part of the serialized payload is the signature
        s = int_to_little_endian(self.version, 4)

        # next in the serialization is the number of inputs
        s += encode_varint(len(self.tx_ins))

        # next we serialize the input to the transaction and sign
        # the specified input for consumption
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                # if there is a redeem script for the transaction, use it
                # as the script_sig (20 byte hash160 of the script)
                if redeem_script:
                    script_sig = redeem_script
                else:
                    script_sig = tx_in.script_pubkey(self.testnet)
            else:
                script_sig = None
            b = TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                seq=tx_in.sequence,
            ).serialize()
            s += b 
    
        # next, we serialize the number of outputs for the transaction
        s += encode_varint(len(self.tx_outs))

        # next we serialize each output within the payload
        for tx_out in self.tx_outs:
            s += tx_out.serialize()

        res = ''.join(format(x, '02x') for x in s)
        print(res)

        # next we set the locktime for the transaction
        s += int_to_little_endian(self.locktime, 4)

        # finally, we set the signature flag to allow anyone to sign
        s += int_to_little_endian(SIGHASH_ALL, 4)

        # now we hash the serialization to get the transaction hash
        h256 = hash256(s)

        # return the payload as an int
        return int.from_bytes(h256, 'big')

    def verify_input(self, input_index) -> bool :
        # get the specified tx_in
        tx_in = self.tx_ins[input_index]

        # get the script pubkey for the transaction input
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)

        # check the format of the script pubkey which will tell us 
        # how to validate the transaction
        # check if it is a p2sh, meaning we need the script engine
        if script_pubkey.is_p2sh_script_pubkey():
            # need the redeem script now
            command = tx_in.script_sig.commands[-1]

            # read in the redeem script as a little endian number
            raw_redeem = int_to_little_endian(len(command), 1) + command
            redeem_script = Script.parse(BytesIO(raw_redeem))
        
            # now check if we have a p2pkh
            if redeem_script.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index, redeem_script)
                witness = tx_in.witness
            elif redeem_script.is_p2wsh_script_pubkey():
                # handle p2sh-p2wpkh

                # get the last element of the witness items
                command = tx_in.witness[-1]
                raw_witness = encode_varint(len(command)) + command
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash(
                    input_index=input_index,
                    witness_script=witness_script,
                )
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index, redeem_script)
                witness = None
        else:
            if script_pubkey.is_p2wpkh_script_pubkey():
                z = self.sig_hash_big143(input_index)
                witness = None
            elif script_pubkey.is_p2wsh_script_pubkey():
                # handle p2wsh

                command = tx_in.witness[-1]
                raw_witness = encode_varint(len(command)) + command
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash(
                    input_index=input_index,
                    witness_script=witness_script,
                )
                witness = tx_in.witness\

            else:
                z = self.sig_hash(input_index)
                witness = None
            
        combined_script = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
        return combined_script.evaluate(z, witness)
    
    def hash_prevouts(self):
        if self._hash_outputs is None:
            all_prevouts = b''
            all_sequence = b''

            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index,4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = hash256(all_prevouts)
            self._hash_squence = hash256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()
        return self._hash_squence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)

    def sig_hash_bip143(self, input_index, redeem_script, witness_script=None):
        '''returns the integer representation of the hash that needs to get
        signed for the index input_index'''

        # get a local ref to the tx
        tx_in = self.tx_ins[input_index]

        # now, just following the BIP143 spec....
        # because thats what the code said to do haha
        s = int_to_little_endian(self.verion,4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)

        # witch based on the type of transaction we are using
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.cmds[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(self.testnet).cmds[1]).serialize()

        s += script_code
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(hash256(s), )

    # def verify_input(self, input_index) -> bool:
    #     """verify and input can be spent by this wallet"""
    #     # get the tx referenced by index
    #     tx_in = self.tx_ins[input_index]

    #     # get the script public key for the specified tx
    #     script_pubkey = tx_in.script_pubkey(testnet=self.testnet)

    #     # check if the pubkey is a p2sh type pubkey
    #     if script_pubkey.is_p2sh_script_pubkey():
    #         cmd = tx_in.script_sig.cmds[-1]
    #         raw_redeem = encode_varint(len(cmd)) + cmd
    #         redeem_script = Script.parse(BytesIO(raw_redeem))
    #     else:
    #         redeem_script = None

    #     # get the script_sig hash
    #     z = self.sig_hash(input_index, redeem_script)

    #     # create the combined script 
    #     combined = tx_in.script_sig + script_pubkey

    #     # evaluate the script to determine if the supplied
    #     # script_pubkey is valid for this input allowing it
    #     # to be spent on this transaction
    #     return combined.evaluate(z)

    def verify(self) -> bool:
        """verify this transaction"""

        # this makes sure we are not creating bitcoins out of thin air
        if self.fee() < 0:
            return False

        # verify each input to the transaction can be spent by verifying each
        # inputs ScriptSig hash
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        
        # if the inputs are verified, we are good to verify the transaction
        return True

    def is_coinbase(self) -> bool:
        """checks if *this* transaction is a coinbase transaction"""

        # first check that the number of inputs is 1
        if len(self.tx_ins) != 1:
            return False

        # next check that the previous hash of the input tx is 0's
        if self.tx_ins[0].prev_tx != 32 * b'\x00':
            return False
        
        # next check if the previous index of the output is all f's
        if self.tx_ins[0].prev_index != 0xffffffff:
            return False
        
        return True
    
    def coinbase_height(self) -> int:
        """return the coinbase height from a coinbase transaction"""

        # check if the transaction is a coinbase transaction first
        if not self.is_coinbase():
            return None

        # the first cmd in the ScriptSig is the height for the first input
        height = self.tx_ins[0].script_sig.cmds[0]

        # the heigh is encoded as little endian so return it as little endian bytes
        return little_endian_to_int(height)
    
    def coinbase_block_subsidy(self):
        """Returns the calculated block subsidy of this coinbase transaction in Satoshis"""
        # grab the height using coinbase_height
        height = self.coinbase_height()
    
        # if the height is None return None
        if height is None:
            return None
    
        # calculate the epoch (height / 210,000) rounded down
        epoch = height // 210000
    
        # return the initial subsidy right-shifted by the epoch
        return 5000000000 >> epoch

class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, seq=0xffffffff) -> None:
        self.prev_tx = prev_tx
        self.prev_index = prev_index

        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        
        self.sequence = seq

        self.witness = None

    def __repr__(self) -> str:
        return "{}:{}".format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        """
            Takes a bytestream and parses the tx_input at the start and returns a tx_in object
        """

        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        val = s.read(4)
        sequence = little_endian_to_int(val)
        return cls(prev_tx, prev_index, script_sig, sequence)
    
    def serialize(self):
        """returns the byte serialization of the transaction input"""
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(
            self.prev_tx.hex(), testnet=testnet
        )
    
    def value(self, testnet=False):
        """get the output value by looking up the tx hash.
        Returns the amount in satoshi"""
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        """Get the ScribPubKey by looking up the tx hash.
        Returns a Script object"""

        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey

class TxOut:
    def __init__(self, amount, script_pubkey) -> None:
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self) -> str:
        return "{}:{}".format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s) -> object:
        """Take a byte stream and parses the tx_outputf at the start
        Returns a TxOut object
        """

        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey) 

    def serialize(self):
        """returns the byte serialization of the transaction input"""
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://blockstream.info/testnet/api'
        else:
            return 'https://blockstream.info/mainnet/api'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}/raw'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                # raw = bytes.fromhex(response.con)
                raw = response.content
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            # make sure the tx we got matches to the hash we requested
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)