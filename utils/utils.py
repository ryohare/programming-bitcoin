import hashlib

# constants
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256**(0x1d - 3)

def hash160(s):
    '''sha256 followed by ripemd160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    print(s.hex())
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(s):
    return encode_base58(s + hash256(s)[:4])


def decode_base58(s) -> bytes:
    num = 0
    for c in s:
        num *= 58
        idx = BASE58_ALPHABET.index(c)
        num += idx

    print(hex(num)) 
    # convert the bytes to big endian
    combined = num.to_bytes(25, byteorder='big')

    # checksum is the last 4 bytes of the address
    checksum = combined[-4:]

    to_verify = combined[:-4]

    # validate the checksum to see if it is valid
    if hash256( to_verify )[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(checksum, hash256(combined[:-4])[:4]))

    # The first byte is the network prefix and the last 4 are the checksum. 
    # The middle 20 are the actual 20-byte hash (aka hash160).
    return combined[1:-4]


def little_endian_to_int(b):
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length) -> bytes:
    '''endian_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    return n.to_bytes(length, 'little')

def read_varint(s):
    '''read_varint reads a variable integer froe a stream''' 
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i) -> bytes:
    '''encodes an integer as a varint''' 
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4) 
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8) 
    else:
        raise ValueError('integer too large: {}'.format(i))

def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    
    return encode_base58_checksum(prefix + h160)

def h160_to_p2pkh_address(h160, testnet=False):
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    
    return encode_base58_checksum(prefix + h160)

def bits_to_target(bits):
    exponent = bits[-1]
    coeffecient = little_endian_to_int(bits[:-1])
    ret = coeffecient * 256**(exponent - 3)
    return ret

def target_to_bits(target):
    """Turns a target integer back into bits"""
    raw_bytes = target.to_bytes(32,'big')

    # get rid of the leading 0's in the number
    raw_bytes = raw_bytes.lstrip(b'\x00')

    # bits format is a way to express large numbers succinctly
    # supports both negative and positive numbers
    # If the first bit in the coeffecient is a 1, the bits field
    # is interpreted as a negative number
    # target is always positive
    if raw_bytes[0] > 0x7f:
        length = len(raw_bytes)
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        # exponent is how long the number is in base 256
        exponent = len(raw_bytes)

        # coefficient is the first 3 digits of the base 256 number
        coefficient = raw_bytes[:3]

    # coeff is little endian ([::-1]) with the exponent going last in bits format
    new_bits = coefficient[::-1] + bytes([exponent])

    return new_bits


# def calculate_new_bits(previous_bits, time_differential):
#     # make sure it took more that 8 weeks to find the last 2015 blocks
#     # decrease the difficulty
#     if time_differential > TWO_WEEKS * 4:
#         time_differential = TWO_WEEKS * 4
    
#     # check if it took less than 3.5 days to find the last 2015 blocks
#     # increase the difficulty
#     if time_differential < TWO_WEEKS // 4:
#         time_differential = TWO_WEEKS // 4

#     new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
#     return target_to_bits(new_target)

def calculate_new_bits(previous_bits, time_differential):
    '''Calculates the new bits given
    a 2016-block time differential and the previous bits'''
    # if the time differential is greater than 8 weeks, set to 8 weeks
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    # if the time differential is less than half a week, set to half a week
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    # the new target is the previous target * time differential / two weeks
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    # if the new target is bigger than MAX_TARGET, set to MAX_TARGET
    if new_target > MAX_TARGET:
        new_target = MAX_TARGET
    # convert the new target to bits
    return target_to_bits(new_target)


def merkle_parent(hash1, hash2):
    """Takes the binary hashes and calculates the hash256"""
    
    # return the hash256 of hash1 + hash2
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes):
    """Takes a list of binary hashes and returns a list that's half
    the length"""
    
    # if the list has exactly 1 element raise an error
    if len(hashes) == 1:
        raise RuntimeError("Cannot take a parent level with only 1 item")
    
    # if the list has an odd number of elements, duplicate the last one
    #       and put it at the end so it has an even number of elements
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    
    # initialize parent level
    parent_level = []
    
    # loop over every pair (use: for i in range(0, len(hashes), 2))
    for i in range(0, len(hashes), 2):
    
        # get the merkle parent of i and i+1 hashes
        parent = merkle_parent(hashes[i], hashes[i + 1])
    
        # append parent to parent level
        parent_level.append(parent)
    
    # return parent level
    return parent_level

def merkle_root(hashes):
    """Takes a list of binary hashes and returns the merkle root"""
    
    # current level starts as hashes
    current_level = hashes
    
    # loop until there's exactly 1 element
    while len(current_level) > 1:
    
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    
    # return the 1st item of current_level
    return current_level[0]