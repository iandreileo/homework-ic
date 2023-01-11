from DESCommon import DES_CUSTOM, generate_keys
from DESUtil import to_binary, add_pads_if_necessary, hex_to_bin, bin_to_hex, bin_to_text
from Crypto.Cipher import DES
import itertools


import base64
 
# CONVERSION FUNCTIONS
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

try:
    input = raw_input
except NameError:
    pass

def get_bits(plaintext):
    text_bits = []
    for i in plaintext:
        text_bits.extend(to_binary(ord(i)))
    return text_bits

def encrypt(plaintext, key_text):
	keys = generate_keys(key_text)

	text_bits = get_bits(plaintext)
	text_bits = add_pads_if_necessary(text_bits)

	final_cipher = ''
	for i in range(0, len(text_bits), 64):
		final_cipher += DES_CUSTOM(text_bits, i, (i+64), keys)

	# conversion of binary cipher into hex-decimal form
	hex_cipher = ''
	i = 0
	while i < len(final_cipher):
		hex_cipher += bin_to_hex(final_cipher[i:i+4])
		i = i+4
	return hex_cipher

def decrypt(cipher, key_text):
	keys = generate_keys(key_text)

	text_bits = []
	ciphertext = ''
	for i in cipher:
		# conversion of hex-decimal form to binary form
		ciphertext += hex_to_bin(i)
	for i in ciphertext:
		text_bits.append(int(i))

	text_bits = add_pads_if_necessary(text_bits)
	keys.reverse()
	bin_mess = ''
	for i in range(0, len(text_bits), 64):
		bin_mess += DES_CUSTOM(text_bits, i, (i+64), keys)

	i = 0
	text_mess = ''
	while i < len(bin_mess):
		text_mess += bin_to_text(bin_mess[i:i+8])
		i = i+8
	return text_mess.rstrip('\x00')


def pad(text):
    n = len(text) % 32
    return text + (b'\x00' * n)

def main():

	ATTACK_SPACE = 18

	key1 = b'\x05\x03\x01\x00\x00\x00\x00\x00'
	key2 = b'\x06\x04\x02\x00\x00\x00\x00\x00'
	plaintext = 'Hello world! :-)'

	cipher = encrypt(encrypt(plaintext, bytes_to_string(key2)), bytes_to_string(key1))
	print(cipher)

	table = {}

	print("Creating table for k1...")
	for i in itertools.count(0):

			# Convert the integer i to a series of 8 bytes.
			key = ''.join([chr(i >> 8*j & 0xff) for j in range(0, 8)]).encode()
			
			# Encrypt the plaintext; this gives us the 'middle' value. We index the
			# table by this middle value, and store the corresponding key.
			table[encrypt(plaintext, bytes_to_string(key))] = key
			
			# The full search space is 2**64, but for this demo we only need 2**18.
			# if i == 2 ** 64 - 1: 
			if i == 2 ** ATTACK_SPACE - 1:
				break

	print("Searching for k2...")
	for i in itertools.count(0):
			
			# Convert key, initialize cipher.
			key = ''.join([chr(i >> 8*j & 0xff) for j in range(0, 8)]).encode()
			 
			# Decrypt the ciphertext to get a middle value. Check if the middle
			# value is stored in the table. If it is, then we have found both
			# keys.
			mid = decrypt(cipher, bytes_to_string(key))
			if mid in table:
					# k1 = ' '.join(['%02x' % ord(x) for x in table[mid]])
					# k2 = ' '.join(['%02x' % ord(x) for x in key])
					# print("k1: %s\nk2: %s" % (k1, k2))
					print(mid, table[mid], key)
					break
					
			# This should not be necessary, but we don't want an infinite loop, so
			# we will include it just in case.
			# elif i == 2 ** 64 - 1:
			elif i == 2 ** ATTACK_SPACE - 1:
					print("Search failed.")
					break

if __name__ == "__main__":
    main()
