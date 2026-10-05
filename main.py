from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import jwt, JWTError
import random
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI(title="Sistema Login con 2FA")

# Servir archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"

# ==============================================================================
# CONFIGURACIÓN DEL CORREO EMISOR (GMAIL)
# ==============================================================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "pc397785@gmail.com"           # <-- Pon tu correo de Gmail
SENDER_PASSWORD = "nrqd dyro kymg mioh"       # <-- Pega aquí tu clave de 16 letras

def enviar_correo_2fa(destinatario: str, codigo: str):
    """Envia el código 2FA por correo electrónico real vía SMTP"""
    try:
        mensaje = MIMEMultipart()
        mensaje["From"] = SENDER_EMAIL
        mensaje["To"] = destinatario
        mensaje["Subject"] = f"{codigo} es tu código de verificación 2FA"

        cuerpo = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2>Código de Verificación</h2>
                <p>Has solicitado iniciar sesión en el sistema.</p>
                <p>Tu código de seguridad de 6 dígitos es:</p>
                <h1 style="color: #007bff; letter-spacing: 5px;">{codigo}</h1>
                <p>Este código expira en 3 minutos.</p>
                <hr>
                <small>Si no solicitaste este código, ignora este mensaje.</small>
            </body>
        </html>
        """
        mensaje.attach(MIMEText(cuerpo, "html"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, destinatario, mensaje.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error al enviar correo: {e}")
        return False

# Base de datos simulada
USER_DB = {}

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class VerifySchema(BaseModel):
    temp_token: str
    code: str

# Ruta raíz para la pantalla de Login
@app.get("/")
def home():
    return FileResponse("static/login.html")

# Ruta para el Menú Principal / Dashboard
@app.get("/dashboard")
def dashboard():
    return FileResponse("static/dashboard.html")

@app.post("/api/login")
def login(data: LoginSchema):
    user = USER_DB.get(data.email)
    if not user:
        user = {"password": "prude", "otp": None, "otp_expiry": None}
        USER_DB[data.email] = user

    if user["password"] != data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo o contraseña incorrectos"
        )
    
    otp_code = f"{random.randint(100000, 999999)}"
    expiry = datetime.utcnow() + timedelta(minutes=3)
    
    user["otp"] = otp_code
    user["otp_expiry"] = expiry
    
    enviado = enviar_correo_2fa(data.email, otp_code)
    if not enviado:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No se pudo enviar el correo de verificación. Revisa la contraseña de aplicación o el correo emisor."
        )
    
    temp_token_data = {
        "sub": data.email,
        "scope": "2fa_pending",
        "exp": datetime.utcnow() + timedelta(minutes=5)
    }
    temp_token = jwt.encode(temp_token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    return {
        "status": "2fa_required",
        "temp_token": temp_token,
        "message": "Código de verificación enviado a tu correo electrónico"
    }

@app.post("/api/verify-2fa")
def verify_2fa(data: VerifySchema):
    try:
        payload = jwt.decode(data.temp_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "2fa_pending":
            raise HTTPException(status_code=401, detail="Token no válido para 2FA")
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Sesión expirada o token inválido")
    
    user = USER_DB.get(email)
    if not user or not user["otp"]:
        raise HTTPException(status_code=400, detail="Solicitud de código inválida")
    
    if datetime.utcnow() > user["otp_expiry"]:
        user["otp"] = None
        raise HTTPException(status_code=400, detail="El código ha expirado")
    
    if data.code != user["otp"]:
        raise HTTPException(status_code=400, detail="Código incorrecto")
    
    user["otp"] = None
    user["otp_expiry"] = None
    
    session_data = {
        "sub": email,
        "scope": "authenticated",
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    access_token = jwt.encode(session_data, SECRET_KEY, algorithm=ALGORITHM)
    
    return {
        "status": "success",
        "access_token": access_token,
        "message": "Autenticación exitosa"
    }
