import os
import random
import string
import smtplib
from email.mime.text import MIMEText
from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()

# --- BASE DE DATOS FICTICIA / MEMORIA TEMPORAL ---
# Usuario de prueba registrado
USERS_DB = {
    "pc397785@gmail.com": {
        "password": "prude"
    }
}

# Almacenamiento temporal de tokens 2FA y códigos generados
TEMP_2FA_TOKENS = {}

# --- MODELOS DE DATOS (Pydantic) ---
class LoginRequest(BaseModel):
    email: str
    password: str

class Verify2FARequest(BaseModel):
    temp_token: str
    code: str

# --- FUNCIÓN DE ENVÍO DE CORREO (SMTP SSL - Puerto 465) ---
def send_email_code(to_email: str, code: str):
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")

    if not sender_email or not sender_password:
        raise HTTPException(
            status_code=500, 
            detail="Faltan las variables de entorno SENDER_EMAIL o SENDER_PASSWORD en Render."
        )

    msg = MIMEText(f"Tu código de verificación de 2 pasos es: {code}")
    msg["Subject"] = "Código de verificación 2FA"
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        # Uso de SSL directo en el puerto 465 (requerido en Render)
        with smtplib.SMTP_SSL("smtp.gmail.com", 587) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
    except Exception as e:
        print(f"Error enviando correo: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error al enviar el correo con el código: {str(e)}"
        )

# --- RUTAS DE LA API ---

@app.post("/api/login")
def login(data: LoginRequest):
    user = USERS_DB.get(data.email)
    
    # Validar credenciales
    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

    # Generar código aleatorio de 6 dígitos
    code = "".join(random.choices(string.digits, k=6))
    
    # Generar token temporal de sesión
    temp_token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    
    # Guardar en memoria para verificar después
    TEMP_2FA_TOKENS[temp_token] = {
        "email": data.email,
        "code": code
    }

    # Enviar correo con el código
    send_email_code(data.email, code)

    return {
        "status": "2fa_required",
        "temp_token": temp_token
    }

@app.post("/api/verify-2fa")
def verify_2fa(data: Verify2FARequest):
    session_data = TEMP_2FA_TOKENS.get(data.temp_token)

    if not session_data:
        raise HTTPException(status_code=400, detail="Sesión 2FA inválida o expirada")

    if session_data["code"] != data.code:
        raise HTTPException(status_code=400, detail="Código de verificación incorrecto")

    # Código correcto: eliminar token temporal
    email = session_data["email"]
    del TEMP_2FA_TOKENS[data.temp_token]

    return {
        "status": "success",
        "message": "Autenticación exitosa",
        "user": email
    }

# --- SERVIR ARCHIVOS ESTÁTICOS Y RUTAS FRONTEND ---

# Sirve los archivos de la carpeta actual (HTML, CSS, JS)
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
def read_root():
    return FileResponse("login.html")

@app.get("/login.html")
def read_login():
    return FileResponse("login.html")

@app.get("/verify.html")
def read_verify():
    return FileResponse("verify.html")

@app.get("/dashboard.html")
def read_dashboard():
    return FileResponse("dashboard.html")
