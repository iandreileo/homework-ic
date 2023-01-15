
import base64

hex_dict = {'0000': '0', '0001': '1', '0010': '2', '0011': '3', '0100': '4', '0101': '5', '0110': '6', '0111': '7',
          '1000': '8', '1001': '9', '1010': 'a', '1011': 'b', '1100': 'c', '1101': 'd', '1110': 'e', '1111': 'f'}
dec_dict = {'0000': 0, '0001': 1, '0010': 2, '0011': 3, '0100': 4, '0101': 5, '0110': 6, '0111': 7, '1000': 8, '1001': 9,
          '1010': 10, '1011': 11, '1100': 12, '1101': 13, '1110': 14, '1111': 15}


hex_revesred_dict = {v: k for k, v in hex_dict.items()}
dec_reversed_dict = {v: k for k, v in dec_dict.items()}

row_dict = {'00': 0, '01': 1, '10': 2, '11': 3}
column_dict = {'0000': 0, '0001': 1, '0010': 2, '0011': 3, '0100': 4, '0101': 5, '0110': 6, '0111': 7, '1000': 8,
              '1001': 9, '1010': 10, '1011': 11, '1100': 12, '1101': 13, '1110': 14, '1111': 15}

binary_list = []
bin_to_text_dict = {}

for n in range(256):
    b = [0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(0, 8):
        if n % 2:
            b[7 - i] = 1
        n = n // 2
    binary_list.append(b)

k = 0
for i in binary_list:
    string = ''
    for j in i:
        string += str(j)
    bin_to_text_dict[string] = chr(k)
    k += 1


def get_row(s):
    return row_dict[s]


def get_column(s):
    return column_dict[s]


def to_binary(s):
    return binary_list[s]


def bin_to_hex(s):
    return hex_dict[s]


def bin_to_dec(s):
    return dec_dict[s]


def hex_to_bin(s):
    return hex_revesred_dict[s]


def dec_to_bin(s):
    return dec_reversed_dict[s]

def left_shift(s, times):
    # Shiftam cu un numar dat
    for i in range(times):
        s.append(s.pop(0))
    return s


def add_pads_if_necessary(s):
    # Functia pe care folosim pentru a adauga biti lipsa
    # Pana la 64
    number_of_vacancy = len(s) % 64
    need_pads = number_of_vacancy > 0
    if need_pads:
        for i in range(64 - number_of_vacancy):
            s.append(0)
    return s


# Functiile din laboratorul de IC
def _chunks(string, chunk_size):
    for i in range(0, len(string), chunk_size):
        yield string[i:i+chunk_size]
 
def byte_2_bin(bval):
    """
      Transform a byte (8-bit) value into a bitstring
    """
    return bin(bval)[2:].zfill(8)

def _hex(x):
    return format(x, '02x')
 
def hex_2_bin(data):
    return ''.join(f'{int(x, 16):08b}' for x in _chunks(data, 2))
 
def str_2_bin(data):
    return ''.join(f'{ord(c):08b}' for c in data)
 
def bin_2_hex(data):
    return ''.join(f'{int(b, 2):02x}' for b in _chunks(data, 8))
 
def str_2_hex(data):
    return ''.join(f'{ord(c):02x}' for c in data)
 
def bin_2_str(data):
    return ''.join(chr(int(b, 2)) for b in _chunks(data, 8))
 
def hex_2_str(data):
    return ''.join(chr(int(x, 16)) for x in _chunks(data, 2))
 
# XOR FUNCTIONS
def strxor(a, b):  # xor two strings, trims the longer input
    return ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b))
 
def bitxor(a, b):  # xor two bit-strings, trims the longer input
    return ''.join(str(int(x) ^ int(y)) for (x, y) in zip(a, b))
 
def hexxor(a, b):  # xor two hex-strings, trims the longer input
    return ''.join(_hex(int(x, 16) ^ int(y, 16)) for (x, y) in zip(_chunks(a, 2), _chunks(b, 2)))
 
# BASE64 FUNCTIONS
def b64decode(data):
    return bytes_to_string(base64.b64decode(string_to_bytes(data)))
 
def b64encode(data):
    return bytes_to_string(base64.b64encode(string_to_bytes(data)))
 
# PYTHON3 'BYTES' FUNCTIONS
def bytes_to_string(bytes_data):
    return bytes_data.decode()  # default utf-8
 
def string_to_bytes(string_data):
    return string_data.encode()  # default utf-8