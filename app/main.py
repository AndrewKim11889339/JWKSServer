from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

#import key manager and jwt service
from .key_manager import key_manager
from .jwt_service import JWTService

#use fast API for rest api
app = FastAPI(title="JWKS Server")

#initialize JWT service with key manager
jwt_service = JWTService(key_manager)

@app.post("/auth")
def auth(expired: bool = Query(False, description="Issue JWT with expired key")):
    try:
        #gen JWT with jwt service
        token = jwt_service.issue_token(expired=expired)
        return {"token": token}
    except ValueError as e:
        #error if no valid keys
        return JSONResponse(status_code=500, content={"error": str(e)})
