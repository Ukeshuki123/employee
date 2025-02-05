# My Web API

A modern FastAPI-based web API project.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
uvicorn main:app --reload --port 8090
```

3. Access the API:
- API Documentation: http://localhost:8090/docs
- Alternative Documentation: http://localhost:8090/redoc
- Base URL: http://localhost:8090

## Features

- Modern FastAPI framework
- Interactive API documentation (Swagger UI)
- CORS middleware enabled
- Type hints and validation using Pydantic
- Health check endpoint
- Example REST endpoints for items
