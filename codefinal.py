import base64
import os


import bcrypt
import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from streamlit_gsheets import GSheetsConnection


# ---------------------------------------------------------------
# CONFIGURACIÓN Y ESTILOS DE LA PÁGINA
# ---------------------------------------------------------------
st.set_page_config(
    page_title="Gestor de Contraseñas", page_icon="🔒", layout="centered"
)


st.markdown(
    """
<style>
.stButton > button {
    width: 100%;
    border-radius: 10px;
    padding: 0.6rem 1rem;
    font-weight: 600;
}
[data-testid="stTextInput"] input { border-radius: 10px; }
button[role="tab"] { font-weight: 600; }
.titulo { text-align: center; font-size: 2.2rem; font-weight: 700; margin-bottom: 0; }
.subtitulo { text-align: center; opacity: 0.7; margin-bottom: 1.5rem; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------
# CONEXIÓN CON GOOGLE SHEETS
# ---------------------------------------------------------------
conn = st.connection("gsheets", type=GSheetsConnection)




def cargar_datos():
    df = conn.read(ttl=0)
    datos = {"usuarios": {}}


    if df is None or df.empty:
        return datos


    for _, fila in df.iterrows():
        usuario = str(fila["usuario_sistema"]).strip()
        if not usuario or pd.isna(usuario) or usuario == "nan":
            continue


        if usuario not in datos["usuarios"]:
            datos["usuarios"][usuario] = {
                "hash_maestra": str(fila["hash_maestra"]),
                "salt_cifrado": str(fila["salt_cifrado"]),
                "contrasenas": [],
            }


        servicio = str(fila.get("servicio", ""))
        if (
            pd.notna(fila.get("servicio"))
            and servicio.strip()
            and servicio != "nan"
        ):
            datos["usuarios"][usuario]["contrasenas"].append(
                {
                    "servicio": servicio,
                    "usuario": str(fila.get("usuario_servicio", "")),
                    "contrasena_cifrada": str(
                        fila.get("contrasena_cifrada", "")
                    ),
                }
            )


    return datos




def guardar_datos(datos):
    filas = []
    for usuario, info in datos["usuarios"].items():
        if not info["contrasenas"]:
            filas.append(
                {
                    "usuario_sistema": usuario,
                    "hash_maestra": info["hash_maestra"],
                    "salt_cifrado": info["salt_cifrado"],
                    "servicio": "",
                    "usuario_servicio": "",
                    "contrasena_cifrada": "",
                }
            )
        else:
            for c in info["contrasenas"]:
                filas.append(
                    {
                        "usuario_sistema": usuario,
                        "hash_maestra": info["hash_maestra"],
                        "salt_cifrado": info["salt_cifrado"],
                        "servicio": c["servicio"],
                        "usuario_servicio": c["usuario"],
                        "contrasena_cifrada": c["contrasena_cifrada"],
                    }
                )


    df_nuevo = pd.DataFrame(filas)
    conn.update(data=df_nuevo)




# ---------------------------------------------------------------
# SEGURIDAD Y OPERACIONES DE CONTRASEÑAS
# ---------------------------------------------------------------




def derivar_clave(contrasena_maestra, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(contrasena_maestra.encode()))




def registrar_usuario(nombre, contrasena_maestra):
    nombre = nombre.strip()
    if not nombre:
        return False, "El nombre de usuario no puede estar vacío."
    if len(contrasena_maestra) < 8:
        return (
            False,
            "La contraseña maestra debe tener al menos 8 caracteres.",
        )


    datos = cargar_datos()
    if nombre in datos["usuarios"]:
        return False, "Ese nombre de usuario ya existe."


    hash_maestra = bcrypt.hashpw(
        contrasena_maestra.encode(), bcrypt.gensalt()
    ).decode()
    salt = base64.b64encode(os.urandom(16)).decode()


    datos["usuarios"][nombre] = {
        "hash_maestra": hash_maestra,
        "salt_cifrado": salt,
        "contrasenas": [],
    }
    guardar_datos(datos)
    return True, "Usuario registrado correctamente."




def iniciar_sesion(nombre, contrasena_maestra):
    datos = cargar_datos()
    usuario = datos["usuarios"].get(nombre.strip())
    if usuario is None:
        return None
    if not bcrypt.checkpw(
        contrasena_maestra.encode(), usuario["hash_maestra"].encode()
    ):
        return None
    salt = base64.b64decode(usuario["salt_cifrado"])
    return Fernet(derivar_clave(contrasena_maestra, salt))




def agregar_contrasena(
    nombre, fernet, servicio, usuario_servicio, contrasena
):
    datos = cargar_datos()
    cifrada = fernet.encrypt(contrasena.encode()).decode()
    datos["usuarios"][nombre]["contrasenas"].append(
        {
            "servicio": servicio.strip(),
            "usuario": usuario_servicio.strip(),
            "contrasena_cifrada": cifrada,
        }
    )
    guardar_datos(datos)




def obtener_contrasenas(nombre):
    datos = cargar_datos()
    if nombre in datos["usuarios"]:
        return datos["usuarios"][nombre]["contrasenas"]
    return []




def eliminar_contrasena(nombre, indice):
    datos = cargar_datos()
    if nombre in datos["usuarios"] and 0 <= indice < len(
        datos["usuarios"][nombre]["contrasenas"]
    ):
        datos["usuarios"][nombre]["contrasenas"].pop(indice)
        guardar_datos(datos)




def descifrar(fernet, token):
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return "[no se pudo descifrar]"




# ---------------------------------------------------------------
# INTERFAZ DE USUARIO (STREAMLIT)
# ---------------------------------------------------------------
if "usuario_actual" not in st.session_state:
    st.session_state.usuario_actual = None
if "fernet" not in st.session_state:
    st.session_state.fernet = None


st.markdown(
    '<div class="titulo">🔒 Gestor de Contraseñas</div>', unsafe_allow_html=True
)
st.markdown(
    '<div class="subtitulo">Tus contraseñas, protegidas en un solo lugar.</div>',
    unsafe_allow_html=True,
)


# ----- Sin sesión iniciada: login y registro -----
if st.session_state.usuario_actual is None:
    with st.container(border=True):
        st.subheader("¡Bienvenido!")
        st.caption("Ingresá a tu gestor de contraseñas.")


        tab_login, tab_registro = st.tabs(["Iniciar sesión", "Registrarse"])


        with tab_login:
            usuario = st.text_input(
                "Usuario",
                placeholder="👤 Ingresá tu usuario",
                key="login_usuario",
            )
            contraseña = st.text_input(
                "Contraseña maestra",
                type="password",
                placeholder="🔒 Ingresá tu contraseña",
                key="login_clave",
            )
            if st.button("Iniciar sesión"):
                fernet = iniciar_sesion(usuario, contraseña)
                if fernet is not None:
                    st.session_state.usuario_actual = usuario
                    st.session_state.fernet = fernet
                    st.rerun()
                else:
                    st.error("Usuario o contraseña incorrectos")


        with tab_registro:
            nuevo_usuario = st.text_input(
                "Usuario", placeholder="👤 Elegí un usuario", key="reg_usuario"
            )
            nueva_clave = st.text_input(
                "Contraseña maestra",
                type="password",
                placeholder="🔒 Elegí una contraseña",
                key="reg_clave",
            )
            confirmar = st.text_input(
                "Confirmar contraseña",
                type="password",
                placeholder="🔒 Repetí la contraseña",
                key="reg_confirmar",
            )
            if st.button("Registrarse"):
                if not nuevo_usuario or not nueva_clave:
                    st.warning("Completá todos los campos")
                elif nueva_clave != confirmar:
                    st.error("Las contraseñas no coinciden")
                else:
                    ok, mensaje = registrar_usuario(
                        nuevo_usuario, nueva_clave
                    )
                    if ok:
                        st.success(
                            "Usuario registrado. Ahora podés iniciar sesión."
                        )
                    else:
                        st.error(mensaje)


# ----- Con sesión iniciada: panel principal -----
else:
    usuario = st.session_state.usuario_actual
    fernet = st.session_state.fernet


    st.sidebar.write(f"Sesión iniciada como **{usuario}**")
    if st.sidebar.button("Cerrar sesión"):
        st.session_state.usuario_actual = None
        st.session_state.fernet = None
        st.rerun()


    with st.container(border=True):
        st.subheader("Agregar contraseña")
        servicio = st.text_input("Servicio", placeholder="Ej: Instagram")
        usuario_servicio = st.text_input("Usuario del servicio")
        password = st.text_input("Contraseña del servicio", type="password")
        if st.button("Guardar"):
            if servicio and usuario_servicio and password:
                agregar_contrasena(
                    usuario, fernet, servicio, usuario_servicio, password
                )
                st.success("Contraseña guardada")
                st.rerun()
            else:
                st.warning("Completá todos los campos")


    st.subheader("Mis contraseñas")
    guardadas = obtener_contrasenas(usuario)
    if not guardadas:
        st.info("Todavía no guardaste ninguna contraseña.")
    else:
        for i, item in enumerate(guardadas):
            with st.expander(
                f"{item['servicio']} — {item['usuario']}"
            ):
                if st.toggle("Mostrar contraseña", key=f"ver_{i}"):
                    pass_descifrada = descifrar(
                        fernet, item["contrasena_cifrada"]
                    )
                    st.code(pass_descifrada)
                else:
                    st.write("••••••••")
                if st.button("Eliminar", key=f"del_{i}"):
                    eliminar_contrasena(usuario, i)
                    st.rerun()

