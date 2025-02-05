from datetime import timedelta
from typing import List
from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from fastapi.encoders import jsonable_encoder

from . import models, schemas, security
from .database import engine, get_db
from .routers import blog, contact, admin

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="My Web API",
    description="A modern FastAPI-based web API with complete website functionality",
    version="1.0.0"
)

# Configure CORS - Add all your frontend URLs here
origins = [
    "http://localhost:3000",    # React
    "http://localhost:8080",    # Vue.js
    "http://localhost:4200",    # Angular
    "http://localhost:5173",    # Vite
    "http://localhost",         # Basic HTTP
    "http://localhost:8090",    # Your API port
    "http://127.0.0.1:8090",   # Alternative localhost
    "http://127.0.0.1",        # Alternative localhost
    # Add your production URLs when deployed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(blog.router)
app.include_router(contact.router)
app.include_router(admin.router)

# Error handler for all exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
    )

# Authentication endpoints
@app.post("/api/login", response_model=schemas.Token)
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(models.User).filter(models.User.email == form_data.username).first()
        if not user or not security.verify_password(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = security.create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        return JSONResponse(content={
            "access_token": access_token,
            "token_type": "bearer",
            "user": jsonable_encoder(user)
        })
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@app.post("/api/register", response_model=schemas.User)
@app.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    try:
        # Check if email exists
        db_user = db.query(models.User).filter(models.User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Check if username exists
        db_user = db.query(models.User).filter(models.User.username == user.username).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Username already taken")
        
        # Create new user
        hashed_password = security.get_password_hash(user.password)
        db_user = models.User(
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            hashed_password=hashed_password
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return JSONResponse(content=jsonable_encoder(db_user))
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

# User endpoints
@app.get("/users/me", response_model=schemas.User)
async def read_users_me(
    current_user: models.User = Depends(security.get_current_user)
):
    return current_user

@app.put("/users/me", response_model=schemas.User)
async def update_user(
    user_update: schemas.UserBase,
    current_user: models.User = Depends(security.get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Check if email is being changed and if it's already taken
        if user_update.email != current_user.email:
            db_user = db.query(models.User).filter(models.User.email == user_update.email).first()
            if db_user:
                raise HTTPException(status_code=400, detail="Email already registered")
        
        # Check if username is being changed and if it's already taken
        if user_update.username != current_user.username:
            db_user = db.query(models.User).filter(models.User.username == user_update.username).first()
            if db_user:
                raise HTTPException(status_code=400, detail="Username already taken")
        
        for key, value in user_update.dict().items():
            setattr(current_user, key, value)
        
        db.commit()
        db.refresh(current_user)
        return JSONResponse(content=jsonable_encoder(current_user))
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

# Item endpoints
@app.post("/items/", response_model=schemas.Item)
def create_item(
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    token: str = Depends(security.oauth2_scheme)
):
    try:
        payload = security.jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    except security.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = db.query(models.User).filter(models.User.email == email).first()
    db_item = models.Item(**item.dict(), owner_id=user.id)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return JSONResponse(content=jsonable_encoder(db_item))

@app.get("/items/", response_model=List[schemas.Item])
def read_items(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    token: str = Depends(security.oauth2_scheme)
):
    try:
        payload = security.jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
    except security.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    items = db.query(models.Item).offset(skip).limit(limit).all()
    return JSONResponse(content=jsonable_encoder(items))

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to My Web API",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }
