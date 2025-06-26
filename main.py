from typing import Union
from fastapi import FastAPI, HTTPException

app = FastAPI(title = "My First API", description = "This is a sample API", version = "1.0.0")

@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None):
    if item_id < 0:
        raise HTTPException(status_code=400, detail="Item ID must be a positive integer")
    return {"item_id": item_id, "q": q}

@app.post("/items/")
async def create_item(item: dict):
    if "name" not in item or not item["name"]:
        raise HTTPException(status_code=400, detail="Item name is required")
    return {"item": item}
