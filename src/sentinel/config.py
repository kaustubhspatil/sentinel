"""Central configuration.

Secrets live outside the repo (the repo is public). Resolution order:
  1. process environment
  2. SENTINEL_ENV_FILE, if set
  3. ~/.secrets/msp.env
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRETS = Path.home() / ".secrets" / "msp.env"


def load_secrets() -> Path | None:
    """Load the out-of-repo secrets file into the environment. Returns the file used."""
    candidate = Path(os.environ.get("SENTINEL_ENV_FILE", DEFAULT_SECRETS))
    if candidate.is_file():
        load_dotenv(candidate, override=False)
        return candidate
    return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    # Paths
    repo_root: Path = Path(__file__).resolve().parents[2]
    data_dir: Path = Field(default_factory=lambda: Path(__file__).resolve().parents[2] / "data")

    # Backbone
    backbone_host: str | None = None
    backbone_user: str = "azureuser"

    # LLM providers
    gemini_api_key: str | None = None
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_deployment: str | None = None
    gcp_project_id: str | None = None
    gcp_region: str = "northamerica-northeast2"
    ollama_host: str = "http://localhost:11434"

    # Graph
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str | None = None

    # Columnar store
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_user: str = "sentinel"
    clickhouse_password: str | None = None
    clickhouse_db: str = "sentinel"

    # PSA
    github_pat: str | None = None
    github_repo: str | None = None

    @property
    def raw_dir(self) -> Path:
        d = self.data_dir / "raw"
        d.mkdir(parents=True, exist_ok=True)
        return d


load_secrets()
settings = Settings()
