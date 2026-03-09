import httpx


def fetch_url(url: str, timeout: int = 10) -> httpx.Response:
    """Internal HTTP client wrapper used across the application."""
    return httpx.get(url, timeout=timeout, follow_redirects=True)


def fetch_json(url: str) -> dict:
    resp = fetch_url(url)
    resp.raise_for_status()
    return resp.json()
