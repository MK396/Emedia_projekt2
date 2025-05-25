import os
import random
import sys
from sympy import isprime

# genrowanie liczb pierwszych
# argument bity=128 oznacza ze szukamy liczb z przedziału
# od 2^127 do 2^128
def generuj_pierwsze(bity):
    # petla w ktorej beda generowane liczby dopoki nie znajdzie sie liczba pierwsza
    while True:
        # getrandbits() - zwraca liczbe o okreslonym rozmiarze w bitach
        liczba = random.getrandbits(bity)
        if isprime(liczba):
            return liczba

# obliczenie nwd za pomoca algorytmu euklidesa
def nwd(a, b):
    while b > 0:
        pom = a
        a = b
        b = pom % b
    return a

# odwrotnosc modulo sluzy do znalezienia klucza prywatnego d
# d ma byc odwrotnoscia modulo phi liczby e
# (d * e) % phi == 1
# stosujemy do tego rozszerzony algorytm Euklidesa,
# bo dla duzego phi najszybciej sprawdzi możliwości
def odw_modulo(e, phi):
    # liczy najwiekszy wspólny dzielnik dla:
    # a*x + b*y = nwd(a, b)
    def rozszerzone_nwd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            nwd, x1, y1 = rozszerzone_nwd(b % a, a)

            x = y1 - (b//a) * x1
            y = x1
            return nwd, x, y
    nwd, x, y = rozszerzone_nwd(e, phi)
    if nwd != 1:
        raise ValueError('Odwrotność modulo nie istnieje')
    else:
        return x % phi

def generuj_klucze(bity):
    p = generuj_pierwsze(bity)
    q = generuj_pierwsze(bity)
    # na wypadek jakby p i q wygenerowaly sie identyczne
    while p == q:
        q = generuj_pierwsze(bity)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.getrandbits(bity)
    while nwd(e, phi) != 1:
        e += 1
        if e >= phi:
            raise ValueError("Brak liczby względnie pierwszej do phi")

    d = odw_modulo(e, phi)

    return p, q, n, phi, e, d

def wczytaj_bajty(sciezka):
    with open(sciezka, 'rb') as f:
        return f.read()

# bity na inty z poprzedniego projektu
def bytes_to_int(byte_data):
    result = 0
    for byte in byte_data:
        result = result * 256 + int(byte)
    return result

# podzial chunkow z poprzedniego projektu
def parse_chunks(file_bytes):
    index = 8
    chunks = []

    while index < len(file_bytes):
        chunk_len = bytes_to_int(file_bytes[index:index + 4])
        chunk_type = file_bytes[index + 4:index + 8].decode('utf-8')
        data = file_bytes[index + 8:index + 8 + chunk_len]
        crc = file_bytes[index + 8 + chunk_len:index + 12 + chunk_len]
        chunks.append((chunk_type, data, crc))
        index += 12 + chunk_len

    return chunks

# w chunku idat znajduje sie masa bitowa pliku
# # wyciagniecie danych z chunka IDAT i sklejenie ich razem
def dane_idat(chunki):
    return b''.join(dane for (rodzaj_chunka, dane, _) in chunki if rodzaj_chunka == 'IDAT')

def main():
    if len(sys.argv) < 2:
        print("Podaj poprawny format wywołania pliku: python script.py <ścieżka_do_pliku>")
        return

    sciezka = sys.argv[1]

    if not os.path.exists(sciezka):
        print(f"Plik '{sciezka}' nie istnieje.")
        sys.exit(1)

    bity = 1024

    p, q, n, phi, e, d = generuj_klucze(bity)
    print(f"p: {p}")
    print(f"q: {q}")
    print(f"n = p * q: {n}")
    print(f"Funkcja Eulera (phi): {phi}")
    print(f"e: {e}")
    d = odw_modulo(e, phi)
    print(f"d: {d}")


    bajty = wczytaj_bajty(sciezka)
    chunki = parse_chunks(bajty)
    surowe_dane = dane_idat(chunki)

    # wielkość bloku w bajtach
    # dzielimy przez 8 bo chcemy podzielic na bajty oraz przez 2 bo maksymalny rozmiar
    # bloku musi być mniejszy od klucza
    rozmiar_bloku = bity // 16

    # podział na bloki
    bloki = [surowe_dane[i:i + rozmiar_bloku] for i in range(0, len(surowe_dane), rozmiar_bloku)]

    print(f"Liczba bloków: {len(bloki)}")
    print(f"Pierwszy blok: {bloki[0]}")
    print(f"Drugi blok: {bloki[1]}")


if __name__ == "__main__":
    main()