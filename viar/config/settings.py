"""
VIAR application settings.

All sensitive values (API keys, credentials) are loaded from environment
variables. Never hardcode secrets in source code.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application-wide settings loaded from environment variables."""

    # ------------------------------------------------------------------ #
    # LLM providers
    # ------------------------------------------------------------------ #
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    # Which provider to use: "anthropic" | "openai"
    llm_provider: str = Field(default="anthropic", alias="LLM_PROVIDER")
    llm_model: str = Field(default="claude-sonnet-4-6", alias="LLM_MODEL")

    # ------------------------------------------------------------------ #
    # File storage
    # ------------------------------------------------------------------ #
    upload_dir: str = Field(default="/tmp/viar/uploads", alias="UPLOAD_DIR")
    output_dir: str = Field(default="/tmp/viar/reports", alias="OUTPUT_DIR")
    frames_dir: str = Field(default="/tmp/viar/frames", alias="FRAMES_DIR")
    # Max upload size in bytes (default 500 MB)
    max_upload_size: int = Field(default=500 * 1024 * 1024, alias="MAX_UPLOAD_SIZE")

    # ------------------------------------------------------------------ #
    # JIRA integration
    # ------------------------------------------------------------------ #
    jira_url: Optional[str] = Field(default=None, alias="JIRA_URL")
    jira_user: Optional[str] = Field(default=None, alias="JIRA_USER")
    jira_api_token: Optional[str] = Field(default=None, alias="JIRA_API_TOKEN")
    jira_project_key: Optional[str] = Field(default=None, alias="JIRA_PROJECT_KEY")

    # ------------------------------------------------------------------ #
    # Security
    # ------------------------------------------------------------------ #
    # Secret key for signing JWTs / session tokens
    secret_key: str = Field(default="change-me-in-production", alias="SECRET_KEY")
    # Allowed CORS origins
    cors_origins: list[str] = Field(
        default=["http://localhost:5173"],
        alias="CORS_ORIGINS",
    )

    # ------------------------------------------------------------------ #
    # Server
    # ------------------------------------------------------------------ #
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    debug: bool = Field(default=False, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    model_config = {"env_file": ".env", "populate_by_name": True}

    @field_validator("llm_provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = {"anthropic", "openai"}
        if v not in allowed:
            raise ValueError(f"llm_provider must be one of {allowed}")
        return v

    def get_llm_client(self):
        """
        Build and return the configured LLM client.

        Returns a LangChain-compatible chat model. API keys are read
        from environment variables — never passed in source code.
        """
        if self.llm_provider == "anthropic":
            if not self.anthropic_api_key:
                raise ValueError("ANTHROPIC_API_KEY is required when llm_provider=anthropic")
            from langchain_anthropic import ChatAnthropic  # type: ignore[import]
            return ChatAnthropic(
                model=self.llm_model,
                anthropic_api_key=self.anthropic_api_key,
                max_tokens=4096,
            )
        else:
            if not self.openai_api_key:
                raise ValueError("OPENAI_API_KEY is required when llm_provider=openai")
            from langchain_openai import ChatOpenAI  # type: ignore[import]
            return ChatOpenAI(
                model=self.llm_model,
                openai_api_key=self.openai_api_key,
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance (singleton)."""
    return Settings()
