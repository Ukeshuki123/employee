from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="My Web API",
    description="A modern FastAPI-based web API",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Example data model
class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to My Web API"}

# Example endpoints
@app.get("/items")
async def get_items():
    # Placeholder for database integration
    return {"items": []}

@app.post("/items")
async def create_item(item: Item):
    # Placeholder for database integration
    return item

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
