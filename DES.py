from DESUtil import bin_2_str, bytes_to_string, to_binary, add_pads_if_necessary, hex_to_bin, bin_to_hex, get_column, get_row, to_binary, left_shift
from DESConstant import *

# FUNCTII NECESARE PENTRU ALGORITMUL DES

def apply_IP(block):
    # Functia de permutare initiala de care avem nevoie in DES
    # Bazat pe algoritmu si pe poza de pe Wiki
    # https://en.wikipedia.org/wiki/File:DES-main-network.png
    r = []
    r.extend(block)
    for i in range(0, 64):
        r[i] = block[IP[i]]
    return r


def apply_FP(block):
    # Functia de permutare finala de care avem nevoie in DES
    # Bazat pe algoritmu si pe poza de pe Wiki
    # https://en.wikipedia.org/wiki/File:DES-main-network.png
    r = []
    r.extend(block)
    for i in range(0, 64):
        r[i] = block[(FP[i])]
    return r

# / FUNCTII NECESARE PENTRU ALGORITMUL DES


# FUNCTII NECESARE PENTRU CALCULUL F - FEISTEL

def e_box(block):
    # Primul pas din functia F din algoritmul DES
    # Este de a face extensie a Ri la cat este sub-cheia (48)
    # https://en.wikipedia.org/wiki/File:DES-f-function.png
    dummy = []
    for i in range(48):
        dummy.append(block[E[i]])

    r = []
    for i in range(0, 48, 6):
        j = i + 6
        r.append(dummy[i:j])
    return r


def s_box(block):
    # SBOX este o functie noninversabila
    # Acesta este ca un tabel unde ai valorile pentru fiecare
    # Acest SBOX da puterea algoritmului pentru ca e nereversibila
    # Se aplica dupa ce se face XOR in F
    # https://en.wikipedia.org/wiki/File:DES-f-function.png
    for i in range(0, 8):
        row = str(block[i][0]) + str(block[i][-1])
        column = ''
        for j in range(1, 5):
            column += str(block[i][j])
        a = 16 * get_row(row)
        a += get_column(column)
        block.pop(i)
        block.insert(i, to_binary(ord(chr(s[i][a]))))
    r = []
    for i in block:
        r.extend(i[4:8])
    return r


def p_box(block):
    # O functie clasica de permutare pe care o folosim in F
    # https://en.wikipedia.org/wiki/File:DES-f-function.png
    r = []
    r.extend(block)
    for i in range(32):
        r[i] = block[P[i]]
    return r

# / FUNCTII NECESARE PENTRU CALCULUL F - FEISTEL


def iterate(left_block, right_block, keys):
    # Functie prin care aplicam tot algoritmul DES
    # In 16 runde
    # Conform https://en.wikipedia.org/wiki/File:DES-main-network.png
    # Si anume pentru fiecare runda 
    for j in range(0, 16):

        # Aici incepe aplicarea functiei F
        # Care este un use-case al Feistel
        # https://en.wikipedia.org/wiki/Feistel_cipher#/media/File:Feistel_cipher_diagram_en.svg
        
        # Aplicam extinderea la 48 de biti pentru Ri
        d9 = []
        d9.extend(right_block)
        right_block = e_box(right_block)

        # Aplicam XOR intre Ri si cheie
        for i in range(0, 8):
            di = i * 6
            for k in range(0, 6):
                right_block[i][k] ^= keys[j][di + k]

        # Aplicam SBOX conform algoritmului
        right_block = s_box(right_block)

        # Aplicam permutarea
        right_block = p_box(right_block)
        for i in range(0, 32):
            right_block[i] ^= left_block[i]

        left_block = []
        left_block.extend(d9)

    return left_block, right_block


def DES_CUSTOM(text_bits, start, end, keys):
    # Aici vom aplica complet algoritmul DES
    # https://en.wikipedia.org/wiki/File:DES-main-network.png

    block = []
    for i in range(start, end):
        block.append(text_bits[i])

    # Aplicam permutarea initiala
    block = apply_IP(block)

    # Impartim in Li si Ri
    left_block = block[0:32]
    right_block = block[32:64]

    # Aplicam cele 16 runde
    left_block, right_block = iterate(left_block, right_block, keys)

    block = []
    block.extend(right_block)
    block.extend(left_block)

    # Aplicam permutarea finala
    block = apply_FP(block)

    cipher_block = ''
    for i in block:
        cipher_block += str(i)
    return cipher_block


def generate_keys(key_text):
    # Functie prin care generam cheile
    # Pentru ca pentru fiecare runda avem nevoie de alta cheie
    key = []
    for i in key_text:
        key.extend(to_binary(ord(i)))

    C = []
    D = []
    r = []

    # Acesta functie a fost gandita pe baza acestei explicatii
    # https://www.tutorialspoint.com/what-are-the-following-steps-for-the-key-generation-of-des-in-information-security
    # Prin shiftarea blockurilor
    for i in range(28):
        C.append(key[PC1_C[i]])
    for i in range(28):
        D.append(key[PC1_D[i]])
    for i in range(0, 16):
        if i in [0, 1, 8, 15]:
            C = left_shift(C, 1)
            D = left_shift(D, 1)
        else:
            C = left_shift(C, 2)
            D = left_shift(D, 2)
        CD = []
        CD.extend(C)
        CD.extend(D)
        dummy = []
        for i in range(48):
            dummy.append(CD[PC2[i]])
        r.append(dummy)
    return r


# IMPLEMENTAREA PROPRIU-ZIS
# PENTRU ENCRYPT SI DECRYPT

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
		text_mess += bin_2_str(bin_mess[i:i+8])
		i = i+8
	return text_mess.rstrip('\x00')

# / IMPLEMENTAREA PROPRIU-ZIS
# / PENTRU ENCRYPT SI DECRYPT