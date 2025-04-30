from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import Response
from jose import jwt
from authlib.jose import jwt, JsonWebKey
import httpx
import xml.etree.ElementTree as ET
import os
from dotenv import load_dotenv  

load_dotenv(override=False)
app = FastAPI()

# Replace with your actual tenant ID and client ID (App Registration ID)
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys"
print(JWKS_URL)

async def validate_token(token: str):
    async with httpx.AsyncClient() as client:
        resp = await client.get(JWKS_URL)
        jwks_data = resp.json()

    try:
        # This does all the key matching and decoding
        claims = jwt.decode(token, JsonWebKey.import_key_set(jwks_data), claims_options={
            "aud": {"essential": True, "value": f"api://{CLIENT_ID}"},
            "exp": {"essential": True},
            "iss": {"essential": True, "value": f"https://sts.windows.net/{TENANT_ID}/"},
        })
        claims.validate()  # Enforce expiration, audience, issuer
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")

@app.post("/soap")
async def soap_endpoint(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    
    token = authorization.split(" ")[1]
    decoded = await validate_token(token)

    # Prepare decoded claims in XML format
    claims_xml = "".join(f"<{k}>{v}</{k}>" for k, v in decoded.items())

    # Construct the SOAP response
    soap_response = f"""<?xml version="1.0" encoding="UTF-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <AuthResult>
          <Message>Your SOAP CALL is AUTHENTICATED with Oauth2.0</Message>
          <TokenClaims>
            {claims_xml}
          </TokenClaims>
        </AuthResult>
      </soap:Body>
    </soap:Envelope>"""

    return Response(content=soap_response, media_type="application/soap+xml")

@app.get("/soap")
async def soap_endpoint(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    
    token = authorization.split(" ")[1]
    decoded = await validate_token(token)

    # Prepare decoded claims in XML format
    claims_xml = "".join(f"<{k}>{v}</{k}>" for k, v in decoded.items())

    # Construct the SOAP response
    soap_response = f"""<?xml version="1.0" encoding="UTF-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <AuthResult>
          <Message>Your SOAP CALL is AUTHENTICATED with Oauth2.0</Message>
          <TokenClaims>
            {claims_xml}
          </TokenClaims>
        </AuthResult>
      </soap:Body>
    </soap:Envelope>"""

    return Response(content=soap_response, media_type="application/soap+xml")

@app.get("/")
def root():
    return {"message": "API is running. Use /docs or POST to /soap"}
