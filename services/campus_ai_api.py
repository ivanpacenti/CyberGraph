from __future__ import annotations

import os
from pathlib import Path

from openai import OpenAI
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

_client: OpenAI | None = None

def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.getenv("CAMPUSAI_API_KEY")
        if not api_key:
            raise RuntimeError("Missing CAMPUSAI_API_KEY in environment")
        _client = OpenAI(
            api_key=api_key,
            base_url=os.getenv("CAMPUSAI_API_URL", "https://api.campusai.compute.dtu.dk/v1"),
        )
    return _client


def get_text_response(
    prompt: str,
    model: str | None = None,
    temperature: float = 0.0,
    timeout: int = 30,
) -> str:
    model = model or os.getenv("CAMPUSAI_MODEL")
    if not model:
        raise RuntimeError("Missing CAMPUSAI_MODEL in environment")

    response = _get_client().chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        timeout=timeout,
    )
    return response.choices[0].message.content