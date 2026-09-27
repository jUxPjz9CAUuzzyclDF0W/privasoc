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
    llm_local_think: bool = False
    llm_timeout: float = 300.0  # seconds per LLM call
    llm_max_tokens: int = 2048
    llm_num_ctx: int = 8192  # Ollama context window (8B Q4 + 8k context fits in 8 GB VRAM)
    llm_remote_url: str = ""
    llm_remote_model: str = ""
    llm_remote_api_key: SecretStr = SecretStr("")
    # D34: automatic API fallback is off unless explicitly enabled
    auto_fallback: bool = False

    vector_bin: str = "vector"
    vector_dir: Path = Path("./vector")
    sample_size: int = 10  # D27: K
    min_coverage: float = 0.8  # I16: a partial parser must cover this share of real lines
    parser_mode: str = "structured"  # D44: structured (regex + mapping) or vrl
    max_attempts: int = 5  # D27: N
    # Step 5: before any remote API call, the local model looks for personal data the
    # detectors missed (refuses the call if the local model is unavailable). Off only if
    # there is no local model at all.
    remote_residual_pass: bool = True
    learn_sample: int = 40  # lines shown to the local model per learning run
    learn_batch: int = 10  # lines per call
    # Reasoning found more names but took ~80 s per 5 lines on an 8 GB GPU; a per-line
    # answer format found them in ~2 s without it (I31). Kept as an option.
    learn_think: bool = False
    learn_max_tokens: int = 2048

    # Step 6: detection, alerts, notifications (D50-D53)
    detect_interval: int = 60  # seconds between detection runs inside `serve` (0 = off)
    alert_dedup_minutes: int = 60
    notify_url: str = ""  # one webhook; empty = no notification
    notify_format: str = "json"  # json | ntfy | discord | slack
    notify_min_level: str = "high"
    public_url: str = ""  # e.g. http://privasoc.lab:8000, only used for links in notifications

    @property
    def sigma_dir(self) -> Path:
        return self.data_dir / "sigma"

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
