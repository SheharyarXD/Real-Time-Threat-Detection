import json
import logging
import time
from uuid import uuid4
from starlette.responses import JSONResponse

logger = logging.getLogger("sentinel.requests")

class SecurityMiddleware:
    def __init__(self, app, settings): self.app, self.settings = app, settings
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http": return await self.app(scope, receive, send)
        request_id = str(uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        started, status = time.monotonic(), 500
        async def wrapped_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"] += [(b"x-request-id", request_id.encode()), (b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store")]
                if self.settings.secure_cookie: message["headers"].append((b"strict-transport-security", b"max-age=31536000"))
            await send(message)
        try:
            if self.settings.environment == "production" and scope.get("scheme") != "https":
                return await JSONResponse({"code":"tls_required","message":"TLS is required","requestId":request_id},403)(scope,receive,wrapped_send)
            if scope["method"] in {"POST", "PUT", "PATCH"}:
                data, size = [], 0
                while True:
                    chunk = await receive()
                    if chunk["type"] == "http.disconnect": return
                    size += len(chunk.get("body", b""))
                    if size > self.settings.maximum_body_bytes:
                        return await JSONResponse({"code":"body_too_large","message":"Request body exceeds the configured limit","requestId":request_id},413)(scope,receive,wrapped_send)
                    data.append(chunk.get("body",b""))
                    if not chunk.get("more_body",False): break
                consumed = False
                async def replay():
                    nonlocal consumed
                    if consumed: return await receive()
                    consumed = True
                    return {"type":"http.request","body":b"".join(data),"more_body":False}
                await self.app(scope,replay,wrapped_send)
            else: await self.app(scope,receive,wrapped_send)
        finally:
            # No bodies, cookies, query strings, authorization headers or credentials in logs.
            logger.info(json.dumps({"requestId":request_id,"method":scope["method"],"path":scope["path"],"status":status,"durationMs":round((time.monotonic()-started)*1000)}))
