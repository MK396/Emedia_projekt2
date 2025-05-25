import os
import random
import sys
import zlib
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

# szyfrujemy kazdy blok po kolei i dodajemy do listy zaszyfrowanych
# c = (m ^ e) mod n
def szyfrowanie_rsa_ecb(bloki, e, n):
    zaszyfrowane = []
    for blok in bloki:
        m = bytes_to_int(blok)
        c = pow(m, e, n)
        # zamiana spowrotem na bajty
        # każdy blok zapiszemy za pomoca tylu bajtów ile wymaga klucz
        # jeśli c zajmuje mniej bajtów niż wymaga to dopisane są zera od przodu
        zaszyfrowane.append(c.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))
    return zaszyfrowane

def odszyfrowanie_rsa_ecb(zaszyfrowane_bloki, d, n, rozmiar_bloku):
    odszyfrowane = []
    for c_bytes in zaszyfrowane_bloki:
        c = int.from_bytes(c_bytes, byteorder='big')
        m = pow(c, d, n)
        odszyfrowane.append(m.to_bytes(rozmiar_bloku, byteorder='big'))
    return odszyfrowane

def zapisz_obraz(chunki, nowe_idat, sciezka_wy):
    nowe_chunki = []
    idat_done = False
    for typ, dane, crc in chunki:
        if typ == "IDAT" and not idat_done:
            # Nowy CRC
            new_crc = zlib.crc32(b'IDAT' + nowe_idat).to_bytes(4, 'big')
            nowe_chunki.append(("IDAT", nowe_idat, new_crc))
            idat_done = True
        elif typ != "IDAT":
            nowe_chunki.append((typ, dane, crc))
    with open(sciezka_wy, "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        for typ, dane, crc in nowe_chunki:
            f.write(len(dane).to_bytes(4, "big"))
            f.write(typ.encode("utf-8"))
            f.write(dane)
            f.write(crc)

def polacz_bloki(bloki):
    return b''.join(bloki)

def szyfrowanie_rsa_cbc(bloki, e, n, rozmiar_bloku):
    zaszyfrowane = []
    iv = os.urandom(rozmiar_bloku)  # Wektor inicjalizujący
    poprzedni = iv

    for blok in bloki:
        xor_blok = bytes(a ^ b for a, b in zip(blok, poprzedni))
        m = bytes_to_int(xor_blok)
        c = pow(m, e, n)
        c_bytes = c.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        zaszyfrowane.append(c_bytes)
        poprzedni = c_bytes[:rozmiar_bloku]  # tylko tyle bajtów ile ma blok

    return iv, zaszyfrowane

def odszyfrowanie_rsa_cbc(zaszyfrowane_bloki, d, n, rozmiar_bloku, iv):
    odszyfrowane = []
    poprzedni = iv

    for c_bytes in zaszyfrowane_bloki:
        c = int.from_bytes(c_bytes, byteorder='big')
        m = pow(c, d, n)
        m_bytes = m.to_bytes(rozmiar_bloku, byteorder='big')
        blok = bytes(a ^ b for a, b in zip(m_bytes, poprzedni))
        odszyfrowane.append(blok)
        poprzedni = c_bytes[:rozmiar_bloku]

    return odszyfrowane


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

    zdekompresowane = zlib.decompress(surowe_dane)

    # wielkość bloku w bajtach
    # dzielimy przez 8 bo chcemy podzielic na bajty oraz przez 2 bo maksymalny rozmiar
    # bloku musi być mniejszy od klucza
    rozmiar_bloku = bity // 16

    # podział na bloki
    bloki = [zdekompresowane[i:i + rozmiar_bloku] for i in range(0, len(zdekompresowane), rozmiar_bloku)]


    print(f"Liczba bloków: {len(bloki)}")

    # SZYFROWANIE ECB
    zaszyfrowane_bloki_ecb = szyfrowanie_rsa_ecb(bloki, e, n)
    zaszyfrowane_dane_ecb = polacz_bloki(zaszyfrowane_bloki_ecb)
    zaszyfrowane_idat_ecb = zlib.compress(zaszyfrowane_dane_ecb)
    zapisz_obraz(chunki, zaszyfrowane_idat_ecb, "zaszyfrowany_ecb.png")
    print("Zapisano zaszyfrowany obraz RSA-ECB jako zaszyfrowany_ecb.png")

    # DESZYFROWANIE ECB
    dane_zaszyfrowane_ecb = dane_idat(parse_chunks(wczytaj_bajty("zaszyfrowany_ecb.png")))
    rozpakowane_ecb = zlib.decompress(dane_zaszyfrowane_ecb)
    rozmiar_bloku = (n.bit_length() + 7) // 8
    zaszyfrowane_bloki_ecb = [rozpakowane_ecb[i:i + rozmiar_bloku] for i in range(0, len(rozpakowane_ecb), rozmiar_bloku)]
    odszyfrowane_bloki_ecb = odszyfrowanie_rsa_ecb(zaszyfrowane_bloki_ecb, d, n, rozmiar_bloku)
    odszyfrowane_dane_ecb = polacz_bloki(odszyfrowane_bloki_ecb)[:len(zdekompresowane)]
    odszyfrowane_idat_ecb = zlib.compress(odszyfrowane_dane_ecb)
    zapisz_obraz(chunki, odszyfrowane_idat_ecb, "odszyfrowany_ecb.png")
    print("Zapisano odszyfrowany obraz RSA-ECB jako odszyfrowany_ecb.png")

    # SZYFROWANIE CBC
    iv, zaszyfrowane_bloki_cbc = szyfrowanie_rsa_cbc(bloki, e, n, rozmiar_bloku)
    zaszyfrowane_dane_cbc = polacz_bloki(zaszyfrowane_bloki_cbc)
    zaszyfrowane_idat_cbc = zlib.compress(iv + zaszyfrowane_dane_cbc)
    zapisz_obraz(chunki, zaszyfrowane_idat_cbc, "zaszyfrowany_cbc.png")
    print("Zapisano zaszyfrowany obraz RSA-CBC jako zaszyfrowany_cbc.png")

    # DESZYFROWANIE CBC
    dane_zaszyfrowane_cbc = dane_idat(parse_chunks(wczytaj_bajty("zaszyfrowany_cbc.png")))
    rozpakowane_cbc = zlib.decompress(dane_zaszyfrowane_cbc)
    iv_odszyfrowanie = rozpakowane_cbc[:rozmiar_bloku]
    dane_bez_iv = rozpakowane_cbc[rozmiar_bloku:]
    zaszyfrowane_bloki_cbc = [dane_bez_iv[i:i + rozmiar_bloku] for i in range(0, len(dane_bez_iv), rozmiar_bloku)]
    odszyfrowane_bloki_cbc = odszyfrowanie_rsa_cbc(zaszyfrowane_bloki_cbc, d, n, rozmiar_bloku, iv_odszyfrowanie)
    odszyfrowane_dane_cbc = polacz_bloki(odszyfrowane_bloki_cbc)[:len(zdekompresowane)]
    odszyfrowane_idat_cbc = zlib.compress(odszyfrowane_dane_cbc)
    zapisz_obraz(chunki, odszyfrowane_idat_cbc, "odszyfrowany_cbc.png")
    print("Zapisano odszyfrowany obraz RSA-CBC jako odszyfrowany_cbc.png")


if __name__ == "__main__":
    main()