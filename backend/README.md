# Nerdearla Hackaton - Backend API

Backend API desarrollado con FastAPI para el hackaton de Nerdearla.

## Estructura del Proyecto

```
backend/
├── app/
│   ├── __init__.py
│   └── main.py          # Aplicación principal FastAPI
├── tests/               # Tests unitarios
├── alembic/            # Migraciones de base de datos
├── Dockerfile          # Container para desarrollo
├── .env.example        # Variables de entorno de ejemplo
├── requirements.txt    # Dependencias Python
└── README.md          # Este archivo
```

## Configuración Inicial

1. **Clonar el repositorio y navegar al directorio backend:**
   ```bash
   cd backend
   ```

2. **Crear archivo de variables de entorno:**
   ```bash
   cp .env.example .env
   ```
   
   Editar `.env` con tus valores reales.

3. **Instalar dependencias (método local):**
   ```bash
   pip install -r requirements.txt
   ```

## Ejecutar la Aplicación

### Opción 1: Uvicorn (Desarrollo Local)

```bash
# Desde el directorio backend/
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Opción 2: Docker

```bash
# Construir imagen
docker build -t nerdearla-backend .

# Ejecutar container
docker run -p 8000:8000 --env-file .env nerdearla-backend
```

### Opción 3: Docker Compose (Recomendado)

Crear `docker-compose.yml` en el directorio raíz:

```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    env_file:
      - ./backend/.env
    volumes:
      - ./backend:/app
    environment:
      - ENVIRONMENT=development
```

Ejecutar:
```bash
docker-compose up --build
```

## Endpoints Disponibles

### API Base
- **GET /health** - Health check (retorna 200)
- **GET /api/v1/ping** - Ping endpoint (retorna `{"ok": true}`)
- **GET /** - Información básica de la API
- **GET /docs** - Documentación interactiva (Swagger UI)
- **GET /redoc** - Documentación alternativa (ReDoc)

### Autenticación OAuth2
- **GET /auth/login** - Inicia el flujo OAuth2 con Google
- **GET /auth/callback** - Callback de Google OAuth (maneja el código de autorización)
- **GET /auth/logout** - Cierra sesión y borra la cookie
- **GET /auth/me** - Información del usuario autenticado
- **GET /auth/status** - Estado de autenticación actual

## Verificar Funcionamiento

Una vez que la aplicación esté ejecutándose:

1. **Health Check:**
   ```bash
   curl http://localhost:8000/health
   ```
   Debe retornar: `{"status": "healthy", "message": "API is running"}`

2. **Ping:**
   ```bash
   curl http://localhost:8000/api/v1/ping
   ```
   Debe retornar: `{"ok": true}`

3. **Documentación:**
   Visitar: http://localhost:8000/docs

4. **Flujo OAuth2:**
   ```bash
   # Iniciar login
   curl http://localhost:8000/auth/login
   # Esto redirigirá a Google OAuth consent screen
   
   # Verificar estado de autenticación
   curl http://localhost:8000/auth/status
   ```

## Flujo de Autenticación OAuth2

### Configuración de Google OAuth

1. **Crear proyecto en Google Cloud Console:**
   - Ir a [Google Cloud Console](https://console.cloud.google.com/)
   - Crear un nuevo proyecto o seleccionar uno existente
   - Habilitar las APIs necesarias:
     - Google+ API
     - Classroom API
     - Calendar API

2. **Configurar OAuth2 credentials:**
   - Ir a "Credentials" > "Create Credentials" > "OAuth 2.0 Client IDs"
   - Tipo de aplicación: "Web application"
   - Authorized redirect URIs: `http://localhost:8000/auth/callback`
   - Copiar Client ID y Client Secret al archivo `.env`

### Scopes Solicitados

El sistema solicita los siguientes scopes de Google:

- `openid` - Identificación básica del usuario
- `email` - Acceso al email del usuario
- `profile` - Acceso al perfil básico (nombre, foto)
- `https://www.googleapis.com/auth/classroom.courses.readonly` - Lectura de cursos de Classroom
- `https://www.googleapis.com/auth/classroom.coursework.me` - Acceso a tareas del usuario
- `https://www.googleapis.com/auth/classroom.rosters.readonly` - Lectura de listas de clase
- `https://www.googleapis.com/auth/calendar.events.readonly` - Lectura de eventos de Calendar

### Flujo Completo

1. **Inicio de sesión:** `GET /auth/login`
   - Genera un state token para seguridad CSRF
   - Redirige al Google OAuth consent screen
   - Usuario autoriza la aplicación

2. **Callback:** `GET /auth/callback`
   - Recibe el código de autorización de Google
   - Intercambia el código por access_token y refresh_token
   - Obtiene el perfil del usuario
   - Verifica acceso a Google Classroom
   - Crea sesión JWT y cookie httpOnly
   - Guarda refresh_token encriptado en memoria/DB

3. **Verificación:** `GET /auth/me`
   - Retorna información del usuario autenticado
   - Requiere cookie de sesión válida

4. **Cierre de sesión:** `GET /auth/logout`
   - Borra la cookie de sesión
   - Invalida la sesión del servidor

### Seguridad

- **JWT Tokens:** Firmados con SECRET_KEY, expiración de 7 días
- **Refresh Tokens:** Encriptados con Fernet antes del almacenamiento
- **CSRF Protection:** State parameter en OAuth flow
- **HttpOnly Cookies:** Previenen acceso desde JavaScript
- **Secure Cookies:** En producción (HTTPS)
- **SameSite:** Configurado como 'lax'

## Desarrollo

### Ejecutar Tests

```bash
pytest tests/
```

### Migraciones de Base de Datos

```bash
# Generar migración
alembic revision --autogenerate -m "Descripción del cambio"

# Aplicar migraciones
alembic upgrade head
```

## Variables de Entorno

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | ID del cliente OAuth de Google | `914402...` |
| `GOOGLE_CLIENT_SECRET` | Secret del cliente OAuth | `GOCSPX-...` |
| `OAUTH_SCOPES` | Scopes de Google OAuth (separados por espacio) | `openid email profile...` |
| `SECRET_KEY` | Clave secreta para JWT/sesiones | `your-secret-key` |
| `ENCRYPTION_KEY` | Clave para encriptar refresh tokens | `32-char-key` |
| `DATABASE_URL` | URL de conexión a la base de datos | `postgresql://...` |
| `BACKEND_URL` | URL del backend | `http://localhost:8000` |
| `FRONTEND_URL` | URL del frontend | `http://localhost:3000` |
| `ENVIRONMENT` | Entorno de ejecución | `development/production` |

## Tecnologías Utilizadas

- **FastAPI** - Framework web moderno y rápido
- **Uvicorn** - Servidor ASGI
- **SQLAlchemy** - ORM para base de datos
- **Alembic** - Migraciones de base de datos
- **Google Auth** - Autenticación con Google OAuth
- **Pydantic** - Validación de datos
- **pytest** - Framework de testing
- **httpx** - Cliente HTTP asíncrono

## Criterios de Aceptación ✅

- ✅ `/health` responde con status 200
- ✅ `/api/v1/ping` responde con `{"ok": true}`
- ✅ Estructura de carpetas completa
- ✅ Todas las dependencias incluidas
- ✅ Dockerfile funcional
- ✅ Variables de entorno configuradas
