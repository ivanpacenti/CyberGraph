from __future__ import annotations

import os
from pathlib import Path

import requests
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

API_URL = os.getenv("CAMPUSAI_API_URL", "https://api.campusai.compute.dtu.dk/chat/completions")


def send_message(
    prompt: str,
    model: str | None = None,
    temperature: float = 0.0,
    timeout: int = 30,
):
    api_key = os.getenv("CAMPUSAI_API_KEY")
    model = model or os.getenv("CAMPUSAI_MODEL")

    if not api_key:
        raise RuntimeError("Missing CAMPUSAI_API_KEY in environment")

    if not model:
        raise RuntimeError("Missing CAMPUSAI_MODEL in environment")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
    }

    response = requests.post(API_URL, json=payload, headers=headers, timeout=timeout)

    try:
        data = response.json()
    except ValueError:
        raise RuntimeError(f"CampusAI returned non-JSON response: {response.text}")

    if not response.ok:
        raise RuntimeError(f"CampusAI error {response.status_code}: {data}")

    return data


def get_text_response(
    prompt: str,
    model: str | None = None,
    temperature: float = 0.0,
    timeout: int = 30,
) -> str:
    data = send_message(
        prompt=prompt,
        model=model,
        temperature=temperature,
        timeout=timeout,
    )

    if "choices" in data:
        return data["choices"][0]["message"]["content"]

    if "message" in data:
        return data["message"].get("content", "")

    raise RuntimeError(f"Unexpected CampusAI response: {data}")