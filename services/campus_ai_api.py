import os
from pathlib import Path
from dotenv import load_dotenv
import requests


API_URL = "https://chat.campusai.compute.dtu.dk/api/chat/completions"

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

def send_message(prompt: str, model: str = "Gemma 3 (Chat)", temperature: float = 0.0, timeout: int = 30):
    api_key = os.getenv("CAMPUSAI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing CAMPUSAI_API_KEY in environment")

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
        "stream": False,
    }

    response = requests.post(API_URL, json=payload, headers=headers, timeout=timeout)

    try:
        data = response.json()
    except ValueError:
        raise RuntimeError(f"CampusAI returned non-JSON response: {response.text}")

    if not response.ok:
        raise RuntimeError(f"CampusAI error {response.status_code}: {data}")

    return data


def get_text_response(prompt: str, model: str = "Gemma 3 (Chat)", temperature: float = 0.0, timeout: int = 30) -> str:
    data = send_message(prompt=prompt, model=model, temperature=temperature, timeout=timeout)
    return data["choices"][0]["message"]["content"]