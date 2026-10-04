from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    database_url: str = 'sqlite:///./security-doctor.db'
    redis_url: str = 'redis://redis:6379/0'
    github_client_id: str = ''
    github_client_secret: str = ''
    github_callback_url: str = 'http://localhost:8000/api/auth/callback'
    frontend_url: str = 'http://localhost:3000'
    session_secret: str = ''
    token_encryption_key: str = ''
    cookie_secure: bool = True
    runtime_allowed_hosts: str = ''
    browser_socket_dir: str = '/run/asd-browser'
    browser_service_socket: str = '/run/asd-browser/service.sock'
    scan_timeout: int = 240
    max_repository_mb: int = 100
    max_source_files: int = 15000
    max_source_bytes: int = 150_000_000
    source_retention: str = 'delete-after-scan'
    openai_api_key: str = ''
    openai_model: str = ''
    allow_llm_explanations: bool = False
    report_bucket: str = ''
    aws_region: str = ''
@lru_cache
def settings(): return Settings()
