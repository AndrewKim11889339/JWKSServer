from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from .key_manager import key_manager
from .jwt_service import JWTService

app = FastAPI(title="JWKS Server")

jwt_service = JWTService(key_manager)


@app.get("/.well-known/jwks.json")
def jwks():
    # Use the instance, not the class
    return JSONResponse(content=key_manager.get_valid_public_keys())


@app.post("/auth")
def auth(expired: bool = Query(False, description="Issue JWT with expired key")):
    try:
        token = jwt_service.issue_token(expired=expired)
        return {"token": token}
    except ValueError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
