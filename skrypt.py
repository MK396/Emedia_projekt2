import os
import sys
import zlib
import random
from random import randint

from sympy import primerange

# Generowanie klucza RSA

# genrowanie liczb pierwszych
# argument bity=128 oznacza ze szukamy liczb z przedziału
# od 2^127 do 2^128
def generuj_pierwsze(bity=8):
    poczatek = 2 ** (bity - 1)
    koniec = 2 ** bity
    pierwsze = list(primerange(poczatek, koniec))
    return random.choice(pierwsze)

# odwrotnosc modulo sluzy do znalezienia klucza prywatnego d
# d ma byc odwrotnoscia modulo phi liczby e
def odw_modulo(e, phi):
    for d in range(3, phi):
        if (d * e) % phi == 1:
            return d
    raise ValueError("Odwrotnosc modulo nie istnieje")

# obliczenie nwd za pomoca algorytmu euklidesa
def nwd(a, b):
    while b > 0:
        pom = a
        a = b
        b = pom % b
    return a

# generowanie kluczy
def generuj_klucze(bity=8):
    p = generuj_pierwsze(bity)
    q = generuj_pierwsze(bity)
    # na wypadek jakby p i q wygenerowaly sie identyczne
    while p == q:
        q = generuj_pierwsze(bity)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 3
    while nwd(e, phi_n) != 1:
        # zwiekszamy co 2 zeby nie marnowac czasu na liczby parzyste
        e += 2
        if e >= phi_n:
            raise ValueError("Nie znaleziono liczby wzglednie pierwszej do phi(n)")

    d = odw_modulo(e, phi_n)

    klucz_publiczny = e
    klucz_prywatny = d
    iloczyn_p_q = n

    return klucz_publiczny, klucz_prywatny, iloczyn_p_q, phi_n, p, q

def szyfrowanie_rsa(data: bytes, klucz_publiczny, iloczyn_p_q):
    e = klucz_publiczny
    n = iloczyn_p_q
    # (m ^ e) mod n = c
    return [pow(c, e, n) for c in data]


def rozszyfrowanie_rsa(zaszyfrowane_dane, klucz_prywatny, iloczyn_p_q):
    d = klucz_prywatny
    n = iloczyn_p_q
    # (c ^ d) mod n =m
    return bytes([pow(c, d, n) for c in zaszyfrowane_dane])

# Cipher Block Chaining
def szyfrowanie_rsa_cbc(data: bytes, klucz_publiczny, iloczyn_p_q):
    e = klucz_publiczny
    n = iloczyn_p_q
    # lista z zaszyfrowanymi bajtami
    zaszyfrowane = []

    # losowanie wektor poczatkowy iv
    iv = random.randint(0, 255)
    zaszyfrowane.append(iv)

    poprzedni = iv
    for bajt in data:
        # xoruje pierwszy bajt danych z iv
        xor = bajt ^ poprzedni
        # (xor ^ e) mod n
        zaszyfrowany = pow(xor, e, n)
        zaszyfrowane.append(zaszyfrowany)
        # robimy modulo 256 zeby wrocic na dane o rozmiarach w bajtach
        poprzedni = zaszyfrowany % 256
    return zaszyfrowane

def rozszyfrowanie_rsa_cbc(szyfrogram, klucz_prywatny, iloczyn_p_q):
    d = klucz_prywatny
    n = iloczyn_p_q

    iv = szyfrogram[0]
    zaszyfrowane_dane = szyfrogram[1:]

    dane = []
    poprzedni = iv
    for c in zaszyfrowane_dane:
        odszyfrowany = pow(c, d, n)
        oryginalny = odszyfrowany ^ poprzedni
        dane.append(oryginalny)
        poprzedni = c % 256
    return bytes(dane)


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

# zamiana danych IDAT aby zaszyfrowac zdjecie
def replace_idat_data(chunki, nowe_dane):
    nowe_chunki = []
    wstawiono = False
    for rodzaj, dane, crc in chunki:
        if rodzaj != 'IDAT':
            nowe_chunki.append((rodzaj, dane, crc))
        elif not wstawiono:
            skompresowane = zlib.compress(nowe_dane)
            crc = zlib.crc32(b'IDAT' + skompresowane).to_bytes(4, 'big')
            nowe_chunki.append(('IDAT', skompresowane, crc))
            wstawiono = True
    return nowe_chunki

# odbudowanie png
def odbuduj_png(naglowek, chunki):
    png = bytearray(naglowek)
    for rodzaj, dane, crc in chunki:
        png.extend(len(dane).to_bytes(4, 'big'))
        png.extend(rodzaj.encode('utf-8'))
        png.extend(dane)
        png.extend(crc)
    return png


def wczytaj_bajty(sciezka):
    with open(sciezka, 'rb') as f:
        return f.read()


def zapisz_bajty(sciezka, dane):
    with open(sciezka, 'wb') as f:
        f.write(dane)


def main():
    klucz_publiczny, klucz_prywatny, iloczyn_p_q, phi_n, p, q = generuj_klucze(bity=8)

    if len(sys.argv) < 2:
        print("Podaj poprawny format wywołania pliku: python script.py <ścieżka_do_pliku>")
        return

    sciezka = sys.argv[1]

    if not os.path.exists(sciezka):
        print(f"Plik '{sciezka}' nie istnieje.")
        sys.exit(1)

    print("1. Szyfrowanie i odszyfrowanie metoda ECB")
    print("2. Szyfrowanie i odszyfrowanie metoda CBC")
    opcja = input("Co chcesz zrobic: ")


    print(f"Klucz publiczny (e): {klucz_publiczny}")
    print(f"Klucz prywatny (d): {klucz_prywatny}")
    print(f"Iloczyn p * q (n): {iloczyn_p_q}")
    print(f"phi(n): {phi_n}")
    print(f"Liczby pierwsze p: {p}, q: {q}")

    # wczytanie PNG w formie bajtow i podział na chunki
    bajty = wczytaj_bajty(sciezka)
    naglowek = bajty[:8]
    chunki = parse_chunks(bajty)

    surowe_dane = dane_idat(chunki)
    dane_po_dekompresji = zlib.decompress(surowe_dane)

    if opcja == '1':
        zaszyfrowane = szyfrowanie_rsa(dane_po_dekompresji, klucz_publiczny, iloczyn_p_q)
        odszyfrowane = rozszyfrowanie_rsa(zaszyfrowane, klucz_prywatny, iloczyn_p_q)

    elif opcja == '2':

        zaszyfrowane = szyfrowanie_rsa_cbc(dane_po_dekompresji, klucz_publiczny, iloczyn_p_q)
        odszyfrowane = rozszyfrowanie_rsa_cbc(zaszyfrowane, klucz_prywatny, iloczyn_p_q)


    if odszyfrowane == dane_po_dekompresji:
        print("Dane po odszyfrowaniu są zgodne z oryginałem.")
    else:
        print("Błąd: dane po odszyfrowaniu nie są zgodne z oryginałem.")


    zaszyfrowane_bajty = bytes([c % 256 for c in zaszyfrowane])

    zaszyfrowane_chunki = replace_idat_data(chunki, zaszyfrowane_bajty)
    zaszyfrowany_png = odbuduj_png(naglowek, zaszyfrowane_chunki)
    zapisz_bajty(f"zaszyfrowany_{os.path.basename(sciezka)}", zaszyfrowany_png)
    print(f"Zapisano zaszyfrowany plik jako: zaszyfrowany_{os.path.basename(sciezka)}")

    nowe_chunki = replace_idat_data(chunki, odszyfrowane)
    nowy_png = odbuduj_png(naglowek, nowe_chunki)
    zapisz_bajty(f"odszyfrowany_{os.path.basename(sciezka)}", nowy_png)
    print(f"Zapisano odszyfrowany plik jako: odszyfrowany_{os.path.basename(sciezka)}")


if __name__ == "__main__":
    main()