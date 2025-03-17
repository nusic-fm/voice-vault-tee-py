import os
from dstack_sdk import AsyncTappdClient, DeriveKeyResponse, TdxQuoteResponse
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.fernet import Fernet
import base64
from fastapi.responses import FileResponse, Response
import requests
import time
from dotenv import load_dotenv
import aiohttp
from fastapi.middleware.cors import CORSMiddleware
load_dotenv()

app = FastAPI()

# Add CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "The World! Call /derivekey or /tdxquote"}

async def verify_signature_and_derive_key(signature: str, message: str, address: str):
    message_hash = encode_defunct(text=message)
    recovered_address = Account.recover_message(message_hash, signature=signature)
    
    if recovered_address.lower() != address.lower():
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Derive key using the verified address
    client = AsyncTappdClient()
    derive_key = await client.derive_key(address)
    key_bytes = derive_key.toBytes(32)  # Get 32 bytes for encryption key

    return key_bytes.hex()

@app.post("/upload-encrypted-audio")
async def upload_encrypted_audio(
    file: UploadFile = File(...),
    signature: str = Form(...),
    message: str = Form(...),
    address: str = Form(...)
):
    try:
        try:
            encryption_key = await verify_signature_and_derive_key(signature, message, address)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        if not encryption_key:
            raise HTTPException(status_code=400, detail="Encryption key is required")
        # Read the audio file
        try:
            content = await file.read()
        except Exception as e:
            raise HTTPException(status_code=400, detail="File is required")
        
        # Create Fernet cipher for encryption
        fernet = Fernet(base64.b64encode(bytes.fromhex(encryption_key)))
        
        # Encrypt the file content
        encrypted_content = fernet.encrypt(content)

        # Get original file extension and create timestamp filename
        file_extension = os.path.splitext(file.filename)[1]
        current_time = str(int(time.time()))
        file_name = f"{current_time}{file_extension}"
        
        # Create FormData-like structure
        form_data = aiohttp.FormData()
        form_data.add_field('file', 
                          encrypted_content,
                          filename=file_name,
                          content_type='application/octet-stream')

        headers = {
            'Authorization': f'Bearer {os.getenv("PINATA_JWT_SECRET")}'
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.pinata.cloud/pinning/pinFileToIPFS",
                    data=form_data,
                    headers=headers,
                    timeout=30  # Add timeout
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise HTTPException(
                            status_code=response.status,
                            detail=f"Pinata API error: {error_text}"
                        )
                    response_data = await response.json()
                    cid = response_data.get('IpfsHash')
                    if not cid:
                        raise HTTPException(
                            status_code=500,
                            detail="No IPFS hash returned from Pinata"
                        )
                    return {"cid": cid}
        except aiohttp.ClientError as e:
            raise HTTPException(
                status_code=503,
                detail=f"Network error while connecting to Pinata: {str(e)}"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt-audio")
async def decrypt_audio(request: Request):
    try:
        data = await request.json()
        cid = data.get('cid')
        signature = data.get('signature')
        message = data.get('message')
        address = data.get('address')
        if not cid:
            raise HTTPException(status_code=400, detail="CID is required")

        encryption_key = await verify_signature_and_derive_key(signature, message, address)
        if not encryption_key:
            raise HTTPException(status_code=400, detail="Encryption key is required")

        # Download encrypted content from Pinata gateway
        gateway_url = f"{os.getenv('PINATA_GATEWAY_URL')}/ipfs/{cid}"
        async with aiohttp.ClientSession() as session:
            async with session.get(gateway_url) as response:
                if response.status != 200:
                    raise HTTPException(status_code=response.status, detail="Failed to fetch file from IPFS")
                encrypted_content = await response.read()

        # Decrypt the content
        fernet = Fernet(base64.b64encode(bytes.fromhex(encryption_key)))
        decrypted_content = fernet.decrypt(encrypted_content)

        # Return as playable audio
        return Response(
            content=decrypted_content,
            media_type='audio/wav',
            headers={
                'Content-Disposition': f'attachment; filename=decrypted_audio.wav'
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# async def derive_key_from_str(address: str):
#     client = AsyncTappdClient()
#     deriveKey = await client.derive_key('/', address)
#     assert isinstance(deriveKey, DeriveKeyResponse)
#     asBytes = deriveKey.toBytes()
#     assert isinstance(asBytes, bytes)
#     limitedSize = deriveKey.toBytes(32)
#     return {"deriveKey": asBytes.hex(), "derive_32bytes": limitedSize.hex()}

# @app.get("/derivekey")
# async def derivekey():
#     deriveKey = await derive_key_from_str('test')
#     return deriveKey
    
# @app.get("/tdxquote")
# async def tdxquote():
#     client = AsyncTappdClient()
#     tdxQuote = await client.tdx_quote('test')
#     assert isinstance(tdxQuote, TdxQuoteResponse)
#     return {"tdxQuote": tdxQuote}


# @app.post("/derive-key-from-signature")
# async def derive_key_from_signature(request: Request):
#     try:
#         data = await request.json()
#         signature = data.get('signature')
#         message = data.get('message')
#         address = data.get('address')

#         if not all([signature, message, address]):
#             raise HTTPException(status_code=400, detail="Missing required parameters")

#         # Verify the signature
#         encryption_key = await verify_signature_and_derive_key(signature, message, address)
#         return encryption_key
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
