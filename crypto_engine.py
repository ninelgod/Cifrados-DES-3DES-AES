import time
from typing import Tuple
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generar_clave_e_iv(algoritmo: str) -> Tuple[bytes, bytes]:
    """Genera aleatoriamente la clave secreta y el vector de inicialización (IV)

    correspondientes para el algoritmo especificado.
    """
    if algoritmo == "DES":
        clave = get_random_bytes(8)
        iv = get_random_bytes(8)
    elif algoritmo == "3DES":
        clave = DES3.adjust_key_parity(get_random_bytes(24))
        iv = get_random_bytes(8)
    elif algoritmo == "AES":
        clave = get_random_bytes(32)
        iv = get_random_bytes(16)
    else:
        raise ValueError(f"Algoritmo '{algoritmo}' no soportado.")

    return clave, iv


def cifrar(texto_plano: str, algoritmo: str, clave: bytes, iv: bytes) -> Tuple[bytes, float]:
    """Aplica el relleno PKCS7 al texto y lo cifra en modo CBC.

    Retorna los bytes cifrados y el tiempo de ejecución en milisegundos.
    """
    datos_bytes = texto_plano.encode('utf-8')

    if algoritmo == "DES":
        tamano_bloque = DES.block_size
        cifrador = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == "3DES":
        tamano_bloque = DES3.block_size
        cifrador = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == "AES":
        tamano_bloque = AES.block_size
        cifrador = AES.new(clave, AES.MODE_CBC, iv)

    datos_rellenados = pad(datos_bytes, tamano_bloque, style='pkcs7')

    inicio = time.perf_counter()
    texto_cifrado = cifrador.encrypt(datos_rellenados)
    fin = time.perf_counter()

    tiempo_ms = (fin - inicio) * 1000
    return texto_cifrado, tiempo_ms


def descifrar(texto_cifrado: bytes, algoritmo: str, clave: bytes, iv: bytes) -> Tuple[str, float]:
    """Descifra el texto cifrado, remueve el relleno PKCS7 y retorna el texto

    original junto con el tiempo empleado en milisegundos.
    """
    if algoritmo == "DES":
        tamano_bloque = DES.block_size
        descifrador = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == "3DES":
        tamano_bloque = DES3.block_size
        descifrador = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == "AES":
        tamano_bloque = AES.block_size
        descifrador = AES.new(clave, AES.MODE_CBC, iv)

    inicio = time.perf_counter()
    datos_rellenados = descifrador.decrypt(texto_cifrado)
    datos_originales = unpad(datos_rellenados, tamano_bloque, style='pkcs7')
    fin = time.perf_counter()

    texto_descifrado = datos_originales.decode('utf-8')
    tiempo_ms = (fin - inicio) * 1000
    return texto_descifrado, tiempo_ms


def verificar_integridad(original: str, recuperado: str) -> bool:
    """Compara mediante igualdad directa si el texto descifrado coincide

    exactamente con el texto plano original.
    """
    return original == recuperado
