from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

# Import auth router
from .auth import router as auth_router

# Cargar variables de entorno
from pathlib import Path
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

# Debug: Print environment variables
print(f"DEBUG: Loading .env from: {env_path}")
print(f"DEBUG: .env exists: {env_path.exists()}")
print(f"DEBUG: GOOGLE_CLIENT_ID loaded: {bool(os.getenv('GOOGLE_CLIENT_ID'))}")
print(f"DEBUG: GOOGLE_CLIENT_SECRET loaded: {bool(os.getenv('GOOGLE_CLIENT_SECRET'))}")

# Crear instancia de FastAPI
app = FastAPI(
    title="Nerdearla Hackaton API",
    description="Backend API para el hackaton de Nerdearla",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Include routers
app.include_router(auth_router)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("FRONTEND_URL", "http://localhost:3000"),
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Endpoint de health check"""
    return {"status": "healthy", "message": "API is running"}

@app.get("/api/v1/ping")
async def ping():
    """Endpoint de ping para verificar conectividad"""
    return {"ok": True}

@app.get("/")
async def root():
    """Endpoint raíz con información básica de la API"""
    return {
        "message": "Nerdearla Hackaton API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
