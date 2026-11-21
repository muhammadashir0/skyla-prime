"""SKYLA PRIME configuration — environment-driven, no secrets in code."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseModel):
    app_name: str = "SKYLA PRIME"
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    db_path: str = Field(default=os.getenv("SKYLA_DB_PATH") or str(ROOT / "data" / "skyla.db"))
    # API token: if set, all /api/* calls require it (Bearer). Empty = local dev open.
    api_token: str = Field(default=os.getenv("SKYLA_API_TOKEN", ""))
    # Default autonomy ceiling for the deployment (0..4). See docs/SECURITY_ARCHITECTURE.md.
    max_autonomy_level: int = Field(default=int(os.getenv("SKYLA_MAX_AUTONOMY", "2")))
    # Model provider keys (all optional; mock provider always available).
    openai_api_key: str = Field(default=os.getenv("OPENAI_API_KEY", ""))
    anthropic_api_key: str = Field(default=os.getenv("ANTHROPIC_API_KEY", ""))
    google_api_key: str = Field(default=os.getenv("GOOGLE_API_KEY", ""))
    deepseek_api_key: str = Field(default=os.getenv("DEEPSEEK_API_KEY", ""))
    qwen_api_key: str = Field(default=os.getenv("QWEN_API_KEY", ""))
    glm_api_key: str = Field(default=os.getenv("GLM_API_KEY", ""))
    # OpenAI-compatible custom endpoint (e.g. local vLLM/SGLang).
    custom_base_url: str = Field(default=os.getenv("SKYLA_CUSTOM_BASE_URL", ""))
    custom_api_key: str = Field(default=os.getenv("SKYLA_CUSTOM_API_KEY", ""))
    # Connectors (all optional; connectors run in explicit mock mode without them).
    telegram_bot_token: str = Field(default=os.getenv("TELEGRAM_BOT_TOKEN", ""))
    google_oauth_client_id: str = Field(default=os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""))
    google_oauth_client_secret: str = Field(default=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""))
    google_refresh_token: str = Field(default=os.getenv("GOOGLE_REFRESH_TOKEN", ""))
    # Execution sandbox
    sandbox_timeout_s: int = Field(default=30)
    sandbox_memory_mb: int = Field(default=512)
    # Web research
    research_user_agent: str = "SKYLA-PRIME/0.1 (research; contact: operator)"
    research_timeout_s: int = 20
    research_max_bytes: int = 2_000_000


@lru_cache
def get_settings() -> Settings:
    return Settings()
