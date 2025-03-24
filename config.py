import os
from pydantic import BaseSettings, Field
from typing import Optional

class Settings(BaseSettings):
    # MongoDB
    MONGODB_URI: str
    DB_NAME: str = "utdrs"
    
    # API Gateway
    API_GATEWAY_URL: str
    
    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    
    # App
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    MODEL_PATH: str = "ml_models"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    class Config:
        env_file = ".env"

settings = Settings()
