from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    app_name: str = 'Kingdom Manager'
    environment: str = 'production'
    docker_host: str = 'tcp://socket-proxy:2375'
    database_path: str = '/data/kingdom.db'
    scan_interval_seconds: int = 60
    idle_default_seconds: int = 900
    enable_mutations: bool = False


settings = Settings()
