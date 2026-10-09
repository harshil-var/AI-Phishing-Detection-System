from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.api import routes_scan, routes_chat, routes_health

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-grade AI-Powered Phishing Detection and Prevention Platform API.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration for Web Dashboard and Browser Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers under /api/v1
app.include_router(routes_scan.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_chat.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_health.router, prefix=settings.API_V1_PREFIX)

@app.get("/")
def root():
    return {
        "title": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "api_v1": settings.API_V1_PREFIX
    }

# Global Exception Handler (Prevents stack traces leaking to client)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please verify your input and try again."}
    )
