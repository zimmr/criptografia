import os
import math
import sys

# Funções
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

def save_file(encrypted_text):
    with open('encriptado.txt', 'wb') as fbinary:
        fbinary.write(encrypted_text)
    return

def encrypt(file_path):
    # TODO: dividir em blocos
    blocks = get_blocks(file_path)

    previous_block = initialization_vector
    encrypted_text = list()

    # TODO: criptografar blocos
    for block in blocks:
        xor_result = int(block) ^ int(previous_block)

        encrypted_block = xor_result ^ cipher_key
        encrypted_text += encrypted_block

        previous_block = block

    save_file(encrypted_text)
    return

# def encrypt_block(block, previous_block):
#     return

def decrypt(chunks):
    print("não implementado.")
    return


# def verificar_tamanho_arquivo(file_path):
#     file_size_bytes = os.path.getsize(file_path)
#     number_of_chunks = math.ceil(file_size_bytes / 16)

#     print(file_size_bytes)
#     print(number_of_chunks)

#     return


# Script
if (len(sys.argv) < 4):
    print ("erro")
    quit()

file_path = sys.argv[1]
cipher_key = sys.argv[2]
option = sys.argv[3]
initialization_vector = "teste" # TODO: fazer isso

match option:
    case "criptografar":
        print("criptografando...")
        encrypt(file_path)
        quit()
    case "descriptografar":
        print("descriptografando...")
        decrypt(file_path)
        quit()
    case _:
        print("erro: opção inválida.")
        quit()
