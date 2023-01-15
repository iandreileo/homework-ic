from DES import decrypt, encrypt
from DESUtil import bytes_to_string
import itertools
import base64


def main():

	# Ideea 2DES este ca la vremea respectiva
	# Voiau pe cat posibil sa creasca spatiul pentru ca puterea computationala era mica
	# Dar problema e ca asa cum encriptezi si dai outputul ca input in alta alta encriptare
	# La fel si la decriptare, poti da outputul ca input in alta functie de decriptare
	# Asa ca poti itera prin tot spatiul si sa gasesti punctul in care cele 2 sunt egale, iar acolo algoritmul e spart
	ATTACK_SPACE = 14

	# Ca algoritmul sa se termine
	# Cheile trebuie sa fie mai mici decat 2 ^ ATTACK_SPACE
	key1 = b'\x05\x03\x00\x00\x00\x00\x00\x00'
	key2 = b'\x06\x04\x00\x00\x00\x00\x00\x00'
	plaintext = 'Proiectul la IC e misto.'

	# Encriptam de 2 ori 
	cipher = encrypt(encrypt(plaintext, bytes_to_string(key1)), bytes_to_string(key2))

	# Cream tabelul gol
	table = {}

	for i in itertools.count(0):

			# Generam o cheie curenta
			key = ''.join([chr(i >> 8*j & 0xff) for j in range(0, 8)]).encode()
			
			# Adaugam in tabel pe pozitia encriptiei
			# Cheia generata in acest pas
			# Care ne va da valoare care e potentiala pentru a fi matchuita
			table[encrypt(plaintext, bytes_to_string(key))] = key

			# Setam un spatiu de cautare
			# Pentru ca altfel poate intra intr-o bucla
			if i == 2 ** ATTACK_SPACE - 1:
				break

	print("Incepem cautarea.")
	for i in itertools.count(0):
			
			# Generam o cheie curenta
			key = ''.join([chr(i >> 8*j & 0xff) for j in range(0, 8)]).encode()

			# Decriptam ciphertextul in ideea de a gasi valoarea pe care sa o matchuim
			mid = decrypt(cipher, bytes_to_string(key))

			# Testam daca valoarea se afla in tabel
			# Pentru ca daca se afla inseamna ca am gasit cele 2 chei si am spart
			if mid in table:
					# Afisam algoritmul spart
					print(mid, table[mid], key)
					break
					
			# Setam un spatiu de cautare
			# Pentru ca altfel poate intra intr-o bucla
			elif i == 2 ** ATTACK_SPACE - 1:
					print("Spatiu terminat. Nu am gasit nimic.")
					break

if __name__ == "__main__":
    main()
