"""Runtime settings, read from environment variables prefixed PRIVASOC_ (or .env)."""

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PRIVASOC_", env_file=".env", extra="ignore")

    api_token: SecretStr = SecretStr("")
    hmac_key: SecretStr = SecretStr("")
    vault_key: SecretStr = SecretStr("")
    data_dir: Path = Path("./data")
    host: str = "127.0.0.1"
    port: int = 8000

    llm_local_url: str = "http://127.0.0.1:11434/v1"
    llm_local_model: str = ""
    llm_remote_url: str = ""
    llm_remote_model: str = ""
    llm_remote_api_key: SecretStr = SecretStr("")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "privasoc.db"

    @property
    def vault_path(self) -> Path:
        return self.data_dir / "vault.db"

    def require_secrets(self) -> None:
        missing = [
            name
            for name in ("api_token", "hmac_key", "vault_key")
            if not getattr(self, name).get_secret_value()
        ]
        if missing:
            raise RuntimeError(
                f"Missing secrets: {', '.join(missing)}. Run `privasoc init` to generate .env."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
