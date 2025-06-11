import os
import math
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from base64 import b64encode

# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
# from Crypto.Random import get_random_bytes

#### Funções ####
def get_blocks(file_path):
    block_size = 16

    file_size_bytes = os.path.getsize(file_path)
    number_of_blocks = math.ceil(file_size_bytes / block_size)

    file = open(file_path, "rb")

    blocks = list(range(number_of_blocks))

    byte = file.read(block_size)
    while byte:
        blocks.append(byte)
        byte = file.read(block_size)

    return blocks

def format_file_name(file_path, option):
    sufix = "cifrado" if option == "criptografar" else "decifrado"
    return file_path.replace(" cifrado", "").replace(" decifrado", "").split(".")[0] + " " + sufix + ".txt" 
    
def save_file(encrypted_text):
    with open('encriptado.txt', 'wb') as fbinary:
        fbinary.write(encrypted_text)
    return

def encrypt_AES_CBC(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_AES_CBC(ciphertext, key, iv):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data)
    unpadded_data += unpadder.finalize()
    return unpadded_data

def encrypt(file_path, key, iv):
    blocks = get_blocks(file_path)
    filteredBlocks = filter(lambda x: not isinstance(x, int), blocks)

    previous_block = iv
    encrypted_text = list()

    for block in filteredBlocks:
        encrypted_block = encrypt_AES_CBC(block, key, previous_block)
        encrypted_text += encrypted_block
        previous_block = block

    save_file(encrypted_text)
    return

def decrypt(file_path, key):
    blocks = get_blocks(file_path)
    filteredBlocks = filter(lambda x: not isinstance(x, int), blocks)
    reverseBlocks = filteredBlocks.reverse()

    previous_block = initialization_vector
    decrypted_text = list()

    for block in reverseBlocks:
        decrypted_block = decrypt_AES_CBC(block, key, previous_block)
        decrypted_text += decrypted_block
        previous_block = block

    save_file(decrypted_text)
    return

#### End funções ####

#### Script ####
if (len(sys.argv) < 4):
    print ("Erro: Argumentos insuficientes.")
    quit()

file_path = sys.argv[1]
input_key = sys.argv[2]
option = sys.argv[3]

# TODO: gerar
initialization_vector = "teste" # TODO: fazer isso
cipher_key = algorithms.AES(input_key) # TODO: gerar chave

match option:
    case "criptografar":
        print("criptografando...")
        encrypt(file_path, cipher_key, initialization_vector)
        quit()
    case "descriptografar":
        print("descriptografando...")
        decrypt(file_path, cipher_key)
        quit()
    case _:
        print("Erro: Opção inválida.")
        quit()

### End Script ####