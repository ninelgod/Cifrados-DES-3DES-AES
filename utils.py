from typing import List, Dict


def solicitar_texto_valido() -> str:
    """Solicita al usuario ingresar un texto por consola asegurando

    que cumpla con la longitud mínima de 20 caracteres.
    """
    while True:
        texto = input("\nIngrese el texto a cifrar (mínimo 20 caracteres): ").strip()
        if len(texto) >= 20:
            return texto
        print(f"Error: El texto tiene solo {len(texto)} caracteres. Debe tener al menos 20.")


def mostrar_menu() -> str:
    """Despliega el menú principal y retorna la opción elegida."""
    print("\n" + "=" * 45)
    print("      MENÚ DE ALGORITMOS SIMÉTRICOS")
    print("=" * 45)
    print("1. Probar cifrado DES")
    print("2. Probar cifrado 3DES")
    print("3. Probar cifrado AES")
    print("4. Probar los 3 algoritmos y comparar tiempos")
    print("5. Salir")
    return input("Seleccione una opción (1-5): ").strip()


def imprimir_resultado_algoritmo(algoritmo: str, clave: bytes, iv: bytes,
                                 cifrado_hex: str, descifrado: str,
                                 t_cifrado: float, t_descifrado: float,
                                 integridad_ok: bool) -> None:
    """Muestra en consola la información detallada del proceso de cifrado/descifrado."""
    print("\n" + "-" * 65)
    print(f"RESULTADOS: {algoritmo}")
    print("-" * 65)
    print(f"Clave Secreta (Hex) : {clave.hex()}")
    print(f"Vector IV (Hex)     : {iv.hex()}")
    print(f"Texto Cifrado (Hex) : {cifrado_hex}")
    print(f"Tiempo de Cifrado   : {t_cifrado:.5f} ms")
    print(f"Texto Descifrado    : {descifrado}")
    print(f"Tiempo Descifrado  : {t_descifrado:.5f} ms")

    if integridad_ok:
        print("Verificación en código: ÉXITO (Texto recuperado es idéntico)")
    else:
        print("Verificación en código: FALLO (El texto recuperado no coincide)")


def imprimir_tabla_comparativa(resultados: List[Dict]) -> None:
    """Muestra una tabla con la comparación de tiempos e integridad de cada algoritmo."""
    print("\n" + "#" * 65)
    print("CUADRO COMPARATIVO DE RENDIMIENTO")
    print("#" * 65)
    print(f"{'Algoritmo':<10} | {'Cifrado (ms)':<15} | {'Descifrado (ms)':<15} | {'Integridad'}")
    print("-" * 65)
    for res in resultados:
        estado = "CORRECTO" if res["verificado"] else "ERROR"
        print(f"{res['algoritmo']:<10} | {res['t_cifrado']:<15.5f} | {res['t_descifrado']:<15.5f} | {estado}")
    print("-" * 65)
