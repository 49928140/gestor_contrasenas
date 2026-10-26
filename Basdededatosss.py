

import base64
import getpass
import json
import os


import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ARCHIVO = "datos.json"




# =====================================================================
# BASE DE DATOS (JSON)
# =====================================================================


def cargar_datos():
    if not os.path.exists(ARCHIVO):
        return {"usuarios": {}}
    with open(ARCHIVO, "r", encoding="utf-8") as f:
        return json.load(f)




def guardar_datos(datos):
    # Se escribe en un temporal y luego se reemplaza: evita perder datos si se corta
    temporal = ARCHIVO + ".tmp"
    with open(temporal, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)
    os.replace(temporal, ARCHIVO)




# =====================================================================
# SEGURIDAD
# =====================================================================


def derivar_clave(contrasena_maestra, salt):
    """Genera la clave de cifrado a partir de la contraseña maestra + salt.
    La clave NO se guarda en ningún lado: se recalcula en cada inicio de sesión."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(contrasena_maestra.encode()))




def registrar_usuario(nombre, contrasena_maestra):
    """Devuelve (True/False, mensaje)."""
    nombre = nombre.strip()
    if not nombre:
        return False, "El nombre de usuario no puede estar vacío."
    if len(contrasena_maestra) < 8:
        return False, "La contraseña maestra debe tener al menos 8 caracteres."


    datos = cargar_datos()
    if nombre in datos["usuarios"]:
        return False, "Ese nombre de usuario ya existe."


    hash_maestra = bcrypt.hashpw(contrasena_maestra.encode(), bcrypt.gensalt()).decode()
    salt = base64.b64encode(os.urandom(16)).decode()


    datos["usuarios"][nombre] = {
        "hash_maestra": hash_maestra,
        "salt_cifrado": salt,
        "contrasenas": [],
    }
    guardar_datos(datos)
    return True, "Usuario registrado correctamente."




def iniciar_sesion(nombre, contrasena_maestra):
    """Si los datos son correctos devuelve un objeto Fernet (la 'llave' de la sesión).
    Si no, devuelve None. El mensaje de error es el mismo para usuario inexistente
    y contraseña incorrecta, así no se revela qué usuarios existen."""
    datos = cargar_datos()
    usuario = datos["usuarios"].get(nombre.strip())
    if usuario is None:
        return None
    if not bcrypt.checkpw(contrasena_maestra.encode(), usuario["hash_maestra"].encode()):
        return None
    salt = base64.b64decode(usuario["salt_cifrado"])
    return Fernet(derivar_clave(contrasena_maestra, salt))




def agregar_contrasena(nombre, fernet, servicio, usuario_servicio, contrasena):
    datos = cargar_datos()
    cifrada = fernet.encrypt(contrasena.encode()).decode()
    datos["usuarios"][nombre]["contrasenas"].append({
        "servicio": servicio.strip(),
        "usuario": usuario_servicio.strip(),
        "contrasena_cifrada": cifrada,
    })
    guardar_datos(datos)




def buscar_contrasenas(nombre, texto):
    """Devuelve las entradas del usuario cuyo servicio contenga el texto.
    Texto vacío = todas."""
    datos = cargar_datos()
    texto = texto.strip().lower()
    return [
        e for e in datos["usuarios"][nombre]["contrasenas"]
        if texto in e["servicio"].lower()
    ]




def descifrar(fernet, token):
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return "[no se pudo descifrar]"




# =====================================================================
# INTERFAZ DE CONSOLA
# =====================================================================


def pedir_clave(texto):
    """Pide una contraseña sin mostrarla en pantalla (si el entorno lo permite)."""
    try:
        return getpass.getpass(texto)
    except Exception:
        return input(texto + "(se verá en pantalla) ")




def menu_registro():
    print("\n--- REGISTRO ---")
    nombre = input("Nombre de usuario: ")
    clave = pedir_clave("Contraseña maestra (mín. 8 caracteres): ")
    repetir = pedir_clave("Repetí la contraseña maestra: ")
    if clave != repetir:
        print("✗ Las contraseñas no coinciden.")
        return
    ok, mensaje = registrar_usuario(nombre, clave)
    print(("✓ " if ok else "✗ ") + mensaje)




def menu_login():
    print("\n--- INICIAR SESIÓN ---")
    nombre = input("Nombre de usuario: ").strip()
    clave = pedir_clave("Contraseña maestra: ")
    fernet = iniciar_sesion(nombre, clave)
    if fernet is None:
        print("✗ Usuario o contraseña incorrectos.")
        return
    print(f"✓ Sesión iniciada. Bienvenido/a, {nombre}.")
    menu_sesion(nombre, fernet)
    print("Sesión cerrada.")




def menu_sesion(nombre, fernet):
    while True:
        print(f"\n--- MIS CONTRASEÑAS ({nombre}) ---")
        print("1. Cargar contraseña nueva")
        print("2. Buscar contraseñas")
        print("3. Cerrar sesión")
        opcion = input("Elegí una opción: ").strip()


        if opcion == "1":
            servicio = input("Servicio (ej: Gmail, Banco): ")
            usuario_servicio = input("Usuario o mail de ese servicio: ")
            contrasena = pedir_clave("Contraseña a guardar: ")
            if not servicio.strip() or not contrasena:
                print("✗ El servicio y la contraseña no pueden estar vacíos.")
                continue
            agregar_contrasena(nombre, fernet, servicio, usuario_servicio, contrasena)
            print("✓ Contraseña guardada (cifrada).")


        elif opcion == "2":
            texto = input("Buscar servicio (Enter para ver todos): ")
            resultados = buscar_contrasenas(nombre, texto)
            if not resultados:
                print("No se encontraron contraseñas.")
                continue
            print(f"\nSe encontraron {len(resultados)}:")
            for i, e in enumerate(resultados, 1):
                print(f"  {i}. {e['servicio']}  |  usuario: {e['usuario']}  |  contraseña: ********")
            eleccion = input("Número para mostrar la contraseña (Enter para volver): ").strip()
            if eleccion.isdigit() and 1 <= int(eleccion) <= len(resultados):
                e = resultados[int(eleccion) - 1]
                print(f"→ {e['servicio']} | {e['usuario']} | {descifrar(fernet, e['contrasena_cifrada'])}")


        elif opcion == "3":
            return
        else:
            print("Opción inválida.")




def main():
    while True:
        print("\n===== GESTOR DE CONTRASEÑAS (BETA) =====")
        print("1. Registrarme")
        print("2. Iniciar sesión")
        print("3. Salir")
        opcion = input("Elegí una opción: ").strip()
        if opcion == "1":
            menu_registro()
        elif opcion == "2":
            menu_login()
        elif opcion == "3":
            print("Hasta luego.")
            break
        else:
            print("Opción inválida.")




if __name__ == "__main__":
    main()


