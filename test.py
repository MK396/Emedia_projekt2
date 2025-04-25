import os
import sys
import zlib
import random
from sympy import primerange

# ---------------- RSA KEY GENERATION ------------------
def generate_prime(bits=8):
    start = 2**(bits - 1)
    end = 2**bits
    primes = list(primerange(start, end))
    return random.choice(primes)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Brak odwrotności modularnej')
    return x % m

def generate_keys(bits=8):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1:
        e += 2

    d = modinv(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# ---------------- RSA ENCRYPTION/DECRYPTION ------------------
def rsa_encrypt(data: bytes, public_key):
    e, n = public_key
    return [pow(byte, e, n) for byte in data]

def rsa_decrypt(encrypted_data, private_key):
    d, n = private_key
    return bytes([pow(c, d, n) for c in encrypted_data])

# ---------------- PNG CHUNK HANDLING ------------------
def bytes_to_int(byte_data):
    result = 0
    for byte in byte_data:
        result = result * 256 + int(byte)
    return result

def parse_chunks(file_bytes):
    index = 8  # skip PNG signature
    chunks = []
    while index < len(file_bytes):
        chunk_len = bytes_to_int(file_bytes[index:index+4])
        chunk_type = file_bytes[index+4:index+8].decode('utf-8')
        data = file_bytes[index+8:index+8+chunk_len]
        crc = file_bytes[index+8+chunk_len:index+12+chunk_len]
        chunks.append((chunk_type, data, crc))
        index += 12 + chunk_len
    return chunks

# W chunku IDAT znajduje się masa bitowa pliku
def get_idat_data(chunks):
    return b''.join(data for (ctype, data, _) in chunks if ctype == 'IDAT')

def replace_idat_data(chunks, new_data):
    new_chunks = []
    inserted = False
    for chunk_type, data, crc in chunks:
        if chunk_type != 'IDAT':
            new_chunks.append((chunk_type, data, crc))
        elif not inserted:
            compressed = zlib.compress(new_data)
            crc_value = zlib.crc32(b'IDAT' + compressed).to_bytes(4, 'big')
            new_chunks.append(('IDAT', compressed, crc_value))
            inserted = True
    return new_chunks

def reconstruct_png(signature, chunks):
    png = bytearray(signature)
    for chunk_type, data, crc in chunks:
        png.extend(len(data).to_bytes(4, 'big'))
        png.extend(chunk_type.encode('utf-8'))
        png.extend(data)
        png.extend(crc)
    return png

# ---------------- FILE I/O ------------------
def read_file_bytes(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def save_bytes(file_path, data):
    with open(file_path, 'wb') as f:
        f.write(data)

# ---------------- MAIN PROGRAM ------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Użycie: python rsa_png.py <nazwa_plik.png>")
        sys.exit(1)

    input_filename = sys.argv[1]

    if not os.path.exists(input_filename):
        print(f"Plik '{input_filename}' nie istnieje.")
        sys.exit(1)

    # Wczytaj plik i rozbij na chunk'i
    file_bytes = read_file_bytes(input_filename)
    signature = file_bytes[:8]
    chunks = parse_chunks(file_bytes)

    # Wygeneruj klucze RSA
    pub, priv = generate_keys(bits=8)

    # Pobierz i odszyfruj dane IDAT
    compressed_idat_data = get_idat_data(chunks)
    decompressed_idat_data = zlib.decompress(compressed_idat_data)

    # Zaszyfruj i zapisz zaszyfrowaną wersję
    encrypted_idat = rsa_encrypt(decompressed_idat_data, pub)
    with open("encrypted.bin", "wb") as f:
        for val in encrypted_idat:
            f.write(val.to_bytes(2, 'big'))

    # Odtwórz sztuczne "zaszyfrowane" dane (jako bajty)
    encrypted_bytes = b''.join(val.to_bytes(2, 'big') for val in encrypted_idat)


    # Podstaw nowe dane do PNG
    encrypted_chunks = replace_idat_data(chunks, encrypted_bytes)
    encrypted_png = reconstruct_png(signature, encrypted_chunks)

    encrypted_png_path = f"encrypted_{os.path.basename(input_filename)}"
    save_bytes(encrypted_png_path, encrypted_png)

    # Odszyfruj i odtwórz oryginalne dane
    decrypted_bytes = rsa_decrypt(encrypted_idat, priv)
    decrypted_chunks = replace_idat_data(chunks, decrypted_bytes)
    decrypted_png = reconstruct_png(signature, decrypted_chunks)

    decrypted_png_path = f"decrypted_{os.path.basename(input_filename)}"
    save_bytes(decrypted_png_path, decrypted_png)

    print("Szyfrowanie RSA zakończone pomyślnie.")
    print(f"Zaszyfrowany plik PNG zapisany jako: {encrypted_png_path}")
    print(f"Odszyfrowany plik PNG zapisany jako: {decrypted_png_path}")
