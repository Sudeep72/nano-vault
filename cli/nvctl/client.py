"""HTTP client wrapper for nvctl — talks to NanoVault REST API."""
import httpx
from .config import get_active_profile, get_token, load_config


class NVClient:
    def __init__(self):
        config = load_config()
        self.profile_name = config["active_profile"]
        profile = get_active_profile()
        self.base_url = profile["address"]
        self.token = get_token(self.profile_name)

    def _headers(self, auth: bool = True) -> dict:
        h = {"Content-Type": "application/json"}
        if auth and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def request(self, method: str, path: str, json_body: dict = None, auth: bool = True, params: dict = None) -> dict:
        url = f"{self.base_url}{path}"

        with httpx.Client(timeout=30) as client:
            kwargs = {
                "headers": self._headers(auth),
                "params": params,
            }

            if json_body is not None:
                kwargs["json"] = json_body

            resp = client.request(method, url, **kwargs)

        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}

        data["_status_code"] = resp.status_code
        return data

    def get(self, path: str, **kw): return self.request("GET", path, **kw)
    def post(self, path: str, json_body=None, **kw): return self.request("POST", path, json_body, **kw)
    def patch(self, path: str, json_body=None, **kw): return self.request("PATCH", path, json_body, **kw)
    def delete(self, path: str, **kw): return self.request("DELETE", path, **kw)
    def put(self, path: str, json_body=None, **kw): return self.request("PUT", path, json_body, **kw)
