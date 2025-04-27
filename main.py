from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import List, Dict
from fastapi.middleware.cors import CORSMiddleware

import random
import string
from eth_account.messages import encode_defunct
from eth_account import Account

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # Your Next.js URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
users = []
circulars = []
bids = []  # Store bids in a list
user_bit_on_cicular = []
# In-memory database for demo
NONCES = {}

class SignatureData(BaseModel):
    address: str
    signature: str

# Security setup
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=1)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if not user_email:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class TutorCircularCreate(BaseModel):
    title: str
    description: str

class TutorCircularResponse(BaseModel):
    id: int
    title: str
    user_email: str
    description: str
class BidCreate(BaseModel):
    proposal: str

class BidResponse(BaseModel):
    id: int
    circular_id: int
    tutor_email: str
    proposal: str
    status: str
    #accepted: bool = False

@app.post("/signup")
def signup(user: UserCreate):
    for u in users:
        if u["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = {"email": user.email, "password": hash_password(user.password)}
    users.append(new_user)
    print(users)
    return "Ok done"

@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    print("slkdj")
    for u in users:
        if u["email"] == form_data.username and verify_password(form_data.password, u["password"]):
            access_token = create_access_token(data={"sub": u["email"]})
            return {"access_token": access_token, "token_type": "bearer"}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"message": f"Welcome, {payload}!"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# New Route: Create Tutor Circular (Requires Authentication)
@app.post("/circulars", response_model=TutorCircularResponse)
def create_circular(circular: TutorCircularCreate, user_email: str = Depends(get_current_user)):
    print(circular)
    circular_id = len(circulars) + 1
    
    new_circular = {"id": circular_id, "title": circular.title, "user_email": user_email, "description": circular.description}
    circulars.append(new_circular)
    return new_circular

# New Route: Get All Circulars
@app.get("/circulars", response_model=List[TutorCircularResponse])
def get_circulars():
    print(circulars)
    return circulars


@app.post("/circulars/{circular_id}/bids", response_model=BidResponse)
def place_bid(circular_id: int, bid: BidCreate, tutor_email: str = Depends(get_current_user)):
    
    # Check if the circular exists
    #if not any(c["id"] == circular_id for c in circulars):
        #raise HTTPException(status_code=404, detail="Circular not found")
    # Check if this tutor_email already bit on this circular or not
    if any((b["tutor_email"] == tutor_email and b["circular_id"] == circular_id) for b in bids):
        raise HTTPException(status_code=404, detail="You already bit on this offer")


    bid_id = len(bids) + 1
    
    new_bid = {
    "id": bid_id,              # Unique ID of the bid
    "circular_id": circular_id, # The ID of the circular being bid on
    "tutor_email": tutor_email,  # Email of the tutor placing the bid
    "proposal": bid.proposal,   # Proposal text from the tutor
    "status": "pending"          # Default status when bid is created
    }
    
    
    bids.append(new_bid)
    for _ in bids:
        print(_)
    return new_bid


@app.get("/circulars/{circular_id}/bids", response_model=List[BidResponse])
def get_bids(circular_id: int, user_email: str = Depends(get_current_user)):
    # Find the circular and check ownership
    circular = next((c for c in circulars if c["id"] == circular_id), None)
    if not circular:
        raise HTTPException(status_code=404, detail="Circular not found")
    
    if circular["user_email"] != user_email:
        raise HTTPException(status_code=403, detail="You are not allowed to view bids on this circular")
    
    return [b for b in bids if b["circular_id"] == circular_id]


@app.put("/circulars/{circular_id}/bids/{bid_id}/accept")
def accept_bid(circular_id: int, bid_id: int, owner_email: str = Depends(get_current_user)):
    # Check if the circular exists and is owned by the user
    circular = next((c for c in circulars if c["id"] == circular_id and c["user_email"] == owner_email), None)
    if not circular:
        raise HTTPException(status_code=403, detail="You are not the owner of this circular")

    # Find the bid
    bid = next((b for b in bids if b["id"] == bid_id and b["circular_id"] == circular_id), None)
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")

    bid["status"] = "accepted"
    return {"message": "Bid accepted successfully"}

@app.put("/circulars/{circular_id}/bids/{bid_id}/decline")
def decline_bid(circular_id: int, bid_id: int, owner_email: str = Depends(get_current_user)):
    # Check if the circular exists and is owned by the user
    circular = next((c for c in circulars if c["id"] == circular_id and c["user_email"] == owner_email), None)
    if not circular:
        raise HTTPException(status_code=403, detail="You are not the owner of this circular")

    # Find the bid
    bid = next((b for b in bids if b["id"] == bid_id and b["circular_id"] == circular_id), None)
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")

    bid["status"] = "declined"
    return {"message": "Bid declined successfully"}

@app.get("/api/get_nonce")
async def get_nonce(address: str):
    nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    NONCES[address] = nonce
    return {"nonce": nonce}

@app.post("/api/verify_signature")
async def verify_signature(data: SignatureData):
    nonce = NONCES.get(data.address)
    if not nonce:
        raise HTTPException(status_code=400, detail="Nonce not found.")

    message = encode_defunct(text=nonce)
    recovered_address = Account.recover_message(message, signature=data.signature)

    if recovered_address.lower() == data.address.lower():
        # Login successful
        return {"status": "success"}
    else:
        raise HTTPException(status_code=401, detail="Invalid signature.")