#!/usr/bin/env python3

import sys


def cifrar_cesar(texto, desplazamiento):
    resultado = ""

    for caracter in texto:

        if 'A' <= caracter <= 'Z':
            resultado += chr(
                (ord(caracter) - ord('A') + desplazamiento) % 26
                + ord('A')
            )

        elif 'a' <= caracter <= 'z':
            resultado += chr(
                (ord(caracter) - ord('a') + desplazamiento) % 26
                + ord('a')
            )

        else:
            resultado += caracter

    return resultado


def main():

    if len(sys.argv) != 3:
        print("Uso:")
        print('python3 cesar.py "TEXTO" CORRIMIENTO')
        print()
        print('Ejemplo:')
        print('python3 cesar.py "Hola Mundo" 3')
        sys.exit(1)

    texto = sys.argv[1]

    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("Error: el corrimiento debe ser un número entero.")
        sys.exit(1)

    texto_cifrado = cifrar_cesar(texto, desplazamiento)

    print("Texto original :", texto)
    print("Corrimiento    :", desplazamiento)
    print("Texto cifrado  :", texto_cifrado)


if __name__ == "__main__":
    main()