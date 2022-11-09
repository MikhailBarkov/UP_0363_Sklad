from pydantic import BaseSettings
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


class Settings(BaseSettings):
    default_response_class = HTMLResponse

    path: str = "app/static"
    static_files = StaticFiles(directory="app/static")
    name: str = "static"

    host: str = "127.0.0.1"
    port: int = 8000
    reload: bool = True

    jwt_secret: str = 'LRVTDforV_yDBh-fbcPxg6QOnG4EjegiuNJXWUFhOrs'
    jwt_algorithm: str = 'HS256'
    jwt_expires_s: int = 3600

    cookie_name: str = 'access_token'

    database_url: str = 'sqlite:///./db/database.sqlite3'


settings = Settings()
