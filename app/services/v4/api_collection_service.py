"""
API Collection Generator — NanoVault v4.0

Generates Postman/Bruno/curl/Python/JS collections FROM THE LIVE OpenAPI
schema — every generated example reflects the actual current API surface,
so this can never drift from reality the way a hand-maintained collection
would.
"""
from __future__ import annotations
import json


class APICollectionService:

    @staticmethod
    def _extract_endpoints(openapi_schema: dict) -> list[dict]:
        endpoints = []
        for path, methods in openapi_schema.get("paths", {}).items():
            for method, spec in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                endpoints.append({
                    "path": path, "method": method.upper(),
                    "summary": spec.get("summary", ""),
                    "tags": spec.get("tags", []),
                    "operation_id": spec.get("operationId", ""),
                    "requires_body": "requestBody" in spec,
                })
        return endpoints

    @staticmethod
    def generate_postman_collection(openapi_schema: dict, base_url: str = "http://localhost:8000") -> dict:
        endpoints = APICollectionService._extract_endpoints(openapi_schema)
        items = []
        for ep in endpoints:
            items.append({
                "name": ep["summary"] or ep["path"],
                "request": {
                    "method": ep["method"],
                    "header": [
                        {"key": "Authorization", "value": "Bearer {{token}}"},
                        {"key": "Content-Type", "value": "application/json"},
                    ],
                    "url": {"raw": f"{{{{base_url}}}}{ep['path']}", "host": ["{{base_url}}"], "path": ep["path"].strip("/").split("/")},
                    **({"body": {"mode": "raw", "raw": "{}"}} if ep["requires_body"] else {}),
                },
            })
        return {
            "info": {"name": "NanoVault API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "variable": [{"key": "base_url", "value": base_url}, {"key": "token", "value": ""}],
            "item": items,
        }

    @staticmethod
    def generate_bruno_collection(openapi_schema: dict, base_url: str = "http://localhost:8000") -> list[dict]:
        """Bruno .bru files are individual text files per request — return their content as a list."""
        endpoints = APICollectionService._extract_endpoints(openapi_schema)
        files = []
        for ep in endpoints:
            safe_name = ep["path"].strip("/").replace("/", "_") or "root"
            content = (
                f"meta {{\n  name: {ep['summary'] or safe_name}\n  type: http\n}}\n\n"
                f"{ep['method'].lower()} {{\n  url: {base_url}{ep['path']}\n}}\n\n"
                f"headers {{\n  Authorization: Bearer {{{{token}}}}\n  Content-Type: application/json\n}}\n"
            )
            files.append({"filename": f"{safe_name}.bru", "content": content})
        return files

    @staticmethod
    def generate_curl_examples(openapi_schema: dict, base_url: str = "http://localhost:8000") -> list[dict]:
        endpoints = APICollectionService._extract_endpoints(openapi_schema)
        examples = []
        for ep in endpoints:
            cmd = f"curl -X {ep['method']} '{base_url}{ep['path']}' \\\n  -H 'Authorization: Bearer $TOKEN'"
            if ep["requires_body"]:
                cmd += " \\\n  -H 'Content-Type: application/json' \\\n  -d '{}'"
            examples.append({"path": ep["path"], "method": ep["method"], "curl": cmd})
        return examples

    @staticmethod
    def generate_python_examples(openapi_schema: dict, base_url: str = "http://localhost:8000") -> list[dict]:
        endpoints = APICollectionService._extract_endpoints(openapi_schema)
        examples = []
        for ep in endpoints:
            method_lower = ep["method"].lower()
            body_arg = ", json={}" if ep["requires_body"] else ""
            code = (
                f"import httpx\n"
                f"resp = httpx.{method_lower}(\n"
                f"    '{base_url}{ep['path']}',\n"
                f"    headers={{'Authorization': f'Bearer {{token}}'}}{body_arg}\n"
                f")\nprint(resp.json())"
            )
            examples.append({"path": ep["path"], "method": ep["method"], "python": code})
        return examples

    @staticmethod
    def generate_javascript_examples(openapi_schema: dict, base_url: str = "http://localhost:8000") -> list[dict]:
        endpoints = APICollectionService._extract_endpoints(openapi_schema)
        examples = []
        for ep in endpoints:
            body_arg = ",\n  body: JSON.stringify({})" if ep["requires_body"] else ""
            code = (
                f"const resp = await fetch('{base_url}{ep['path']}', {{\n"
                f"  method: '{ep['method']}',\n"
                f"  headers: {{ 'Authorization': `Bearer ${{token}}`, 'Content-Type': 'application/json' }}{body_arg}\n"
                f"}});\nconst data = await resp.json();"
            )
            examples.append({"path": ep["path"], "method": ep["method"], "javascript": code})
        return examples

    @staticmethod
    def get_endpoint_count(openapi_schema: dict) -> dict:
        endpoints = APICollectionService._extract_endpoints(openapi_schema)
        by_tag: dict[str, int] = {}
        for ep in endpoints:
            for tag in ep["tags"] or ["untagged"]:
                by_tag[tag] = by_tag.get(tag, 0) + 1
        return {"total_endpoints": len(endpoints), "by_tag": by_tag}


api_collection_service = APICollectionService()
