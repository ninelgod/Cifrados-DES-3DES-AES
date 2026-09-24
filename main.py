import crypto_engine as engine
import utils


def ejecutar_proceso(algoritmo: str, texto_original: str) -> dict:
    """Ejecuta el flujo completo para un algoritmo determinado."""
    # 1. Generar clave e IV aleatorios
    clave, iv = engine.generar_clave_e_iv(algoritmo)

    # 2. Cifrar
    texto_cifrado, t_cifrado = engine.cifrar(texto_original, algoritmo, clave, iv)

    # 3. Descifrar
    texto_descifrado, t_descifrado = engine.descifrar(texto_cifrado, algoritmo, clave, iv)

    # 4. Verificar integridad programáticamente
    es_valido = engine.verificar_integridad(texto_original, texto_descifrado)

    # 5. Mostrar resultados
    utils.imprimir_resultado_algoritmo(
        algoritmo=algoritmo,
        clave=clave,
        iv=iv,
        cifrado_hex=texto_cifrado.hex(),
        descifrado=texto_descifrado,
        t_cifrado=t_cifrado,
        t_descifrado=t_descifrado,
        integridad_ok=es_valido
    )

    return {
        "algoritmo": algoritmo,
        "t_cifrado": t_cifrado,
        "t_descifrado": t_descifrado,
        "verificado": es_valido
    }


def main():
    print("=========================================================")
    print("   SISTEMA DE CIFRADO Y DESCIFRADO SIMÉTRICO (CBC + PKCS7)")
    print("=========================================================")

    texto_base = utils.solicitar_texto_valido()

    while True:
        opcion = utils.mostrar_menu()

        if opcion == "1":
            ejecutar_proceso("DES", texto_base)
        elif opcion == "2":
            ejecutar_proceso("3DES", texto_base)
        elif opcion == "3":
            ejecutar_proceso("AES", texto_base)
        elif opcion == "4":
            res_lista = []
            for alg in ["DES", "3DES", "AES"]:
                res = ejecutar_proceso(alg, texto_base)
                res_lista.append(res)
            utils.imprimir_tabla_comparativa(res_lista)
        elif opcion == "5":
            print("\n¡Programa finalizado exitosamente!")
            break
        else:
            print("Opción inválida. Intente de nuevo.")


if __name__ == "__main__":
    main()
