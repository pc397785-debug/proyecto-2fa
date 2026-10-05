import os
import random
import smtplib
from email.mime.text import MIMEText
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI()

# Servir archivos estáticos si los tienes en la carpeta actual o static
app.mount("/static", StaticFiles(directory="."), name="static")

# Diccionario temporal en memoria para almacenar tokens y códigos 2FA
db_temp = {}

class LoginData(BaseModel):
    email: str
    password: str

class VerifyData(BaseModel):
    temp_token: str
    code: str

def send_email_code(to_email: str, code: str):
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")

    if not sender_email or not sender_password:
        raise Exception("Faltan las variables de entorno SENDER_EMAIL o SENDER_PASSWORD en Render.")

    msg = MIMEText(f"Tu código de verificación de 2 pasos es: {code}")
    msg["Subject"] = "Código de verificación 2FA"
    msg["From"] = sender_email
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())

@app.get("/", response_class=HTMLResponse)
def get_login_page():
    return FileResponse("login.html")

@app.get("/verify.html", response_class=HTMLResponse)
def get_verify_page():
    return FileResponse("verify.html")

@app.get("/dashboard.html", response_class=HTMLResponse)
def get_dashboard_page():
    return FileResponse("dashboard.html")

@app.post("/api/login")
def login(data: LoginData):
    # Credenciales fijas
    if data.email == "pc397785@gmail.com" and data.password == "prude":
        code = str(random.randint(100000, 999999))
        temp_token = str(random.randint(10000000, 99999999))
        
        try:
            send_email_code(data.email, code)
        except Exception as e:
            raise HTTPException(status_code=500, detail="No se pudo enviar el correo de verificación. Revisa la contraseña de aplicación o el correo emisor.")
        
        db_temp[temp_token] = code
        return {"status": "2fa_required", "temp_token": temp_token}
    
    raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

@app.post("/api/verify")
def verify(data: VerifyData):
    saved_code = db_temp.get(data.temp_token)
    if saved_code and saved_code == data.code:
        del db_temp[data.temp_token]
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Código de verificación incorrecto o expirado")
