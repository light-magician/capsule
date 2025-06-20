# hello_fastapi.py
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def read_root():
    return {"msg": "hello"}
