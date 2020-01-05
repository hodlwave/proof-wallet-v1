import hashlib
import binascii

# Below code ASSUMES binary inputs and compressed pubkeys
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE]
PUBLIC = [MAINNET_PUBLIC, TESTNET_PUBLIC]

code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}

def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00' if base == 256 else b'1' \
        if base == 58 else b'0'
    if (pad_size > 0):
        result_bytes = padding_element*pad_size + result_bytes

    result_string = ''.join([chr(y) for y in result_bytes])
    result = result_bytes if base == 256 else result_string

    return result

def decode(string, base):
    if base == 256 and isinstance(string, str):
        string = bytes(bytearray.fromhex(string))
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 256:
        def extract(d, cs):
            return d
    else:
        def extract(d, cs):
            return cs.find(d if isinstance(d, str) else chr(d))

    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += extract(string[0], code_string)
        string = string[1:]
    return result

def from_byte_to_int(a):
    return a

def from_string_to_bytes(a):
    return a if isinstance(a, bytes) else bytes(a, 'utf-8')

def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg

def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)

def bip32_deserialize(data):
    dbin = changebase(data, 58, 256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = from_byte_to_int(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01' if vbytes in PRIVATE else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)

def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    return hashlib.new('ripemd160', intermed).digest()

def fingerprint(xpub):
    vbytes, depth, fingerprint, i, chaincode, key = bip32_deserialize(xpub)
    fp_bytes = bin_hash160(key)[:4]
    return binascii.hexlify(fp_bytes).decode('ascii').upper()
