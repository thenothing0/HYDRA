"""Bounded Hacker API client; credentials are only sent to HackerOne's API host."""

import asyncio
import json
import os
import re


class HackerOneAPIError(ValueError):
    def __init__(self, status):
        self.status = status
        reasons = {401: "invalid username/token or inactive account", 403: "access or identity verification required",
                   404: "program/resource not accessible", 422: "report or program requirements not satisfied",
                   429: "rate limited; no automatic write retry"}
        super().__init__(f"HackerOne HTTP {status}: {reasons.get(status, 'request failed')}")


def program_handle(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}", value):
        raise ValueError("Use a HackerOne program handle, not a URL or token")
    return value


class HackerOneClient:
    BASE_URL = "https://api.hackerone.com/v1/hackers"

    def __init__(self, *, transport=None):
        import httpx
        from hydra.config import load_environment

        load_environment()
        username = os.getenv("HACKERONE_USERNAME", "")
        self.username = username
        self._token = os.getenv("HACKERONE_API_TOKEN", "")
        if not username or not self._token:
            raise ValueError("Set HACKERONE_USERNAME and HACKERONE_API_TOKEN in local .env; never enter secrets in chat")
        self._auth = httpx.BasicAuth(username, self._token)
        self._transport = transport

    def contains_credential(self, text):
        return self._token in text

    async def request(self, method, path, *, payload=None, params=None):
        import httpx

        if not path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise ValueError("Invalid Hacker API resource")
        try:
            async with httpx.AsyncClient(
                auth=self._auth, timeout=20, follow_redirects=False, trust_env=False,
                transport=self._transport, headers={"Accept": "application/json", "User-Agent": "HYDRA-engineering"},
            ) as client:
                async with client.stream(method, self.BASE_URL + path, json=payload, params=params) as response:
                    if not 200 <= response.status_code < 300:
                        raise HackerOneAPIError(response.status_code)
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 2_000_000:
                            raise ValueError("HackerOne response exceeded the 2 MB limit")
                    data = json.loads(body)
                    if not isinstance(data, dict) or "data" not in data:
                        raise ValueError("Malformed HackerOne response")
                    return data
        except (httpx.HTTPError, json.JSONDecodeError, UnicodeError):
            raise ValueError("HackerOne transport or response failed; credentials and response bodies are withheld") from None

    async def snapshot(self, handle, scope_id):
        handle = program_handle(handle)
        if type(scope_id) is not int or scope_id < 1:
            raise ValueError("A positive structured scope ID is required")
        # Numeric pagination is constructed locally; API-supplied URLs are never followed.
        program = (await self.request("GET", f"/programs/{handle}"))["data"]
        if not isinstance(program, dict) or program.get("attributes", {}).get("handle") != handle:
            raise ValueError("HackerOne program identity mismatch")
        scopes = (await self.request("GET", f"/programs/{handle}/structured_scopes",
                                    params={"filter[id__gt]": scope_id - 1, "page[size]": 100}))["data"]
        if not isinstance(scopes, list):
            raise ValueError("Malformed structured scopes")
        scope = next((item for item in scopes if str(item.get("id")) == str(scope_id)), None)
        if scope is None:
            raise ValueError("Selected asset is not in this program's structured scopes")
        exclusions = await self.collection(f"/programs/{handle}/scope_exclusions")
        weaknesses = await self.collection(f"/programs/{handle}/weaknesses")
        attributes = program["attributes"]
        return {"program": handle, "policy": attributes.get("policy"),
                "submission_state": attributes.get("submission_state"),
                "scope": scope, "exclusions": exclusions, "weaknesses": weaknesses}

    async def collection(self, path):
        records = []
        for page in range(1, 21):
            response = await self.request("GET", path, params={"page[number]": page, "page[size]": 100})
            items = response["data"]
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ValueError("Malformed program collection")
            records.extend(items)
            if len(json.dumps(records)) > 500000:
                raise ValueError("Program collection exceeds the verification limit")
            links = response.get("links") or {}
            if not links.get("next") and (len(items) < 100 or "next" in links):
                break
        else:
            raise ValueError("Program pagination exceeded the verification limit")
        return records

    async def create_report(self, attributes):
        return await asyncio.wait_for(
            self.request("POST", "/reports", payload={"data": {"type": "report", "attributes": attributes}}),
            timeout=25,
        )
