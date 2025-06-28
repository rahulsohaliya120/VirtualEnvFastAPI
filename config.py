import os
from dotenv import load_dotenv
from typing import cast

load_dotenv()

SECRET_KEY = cast(str, os.getenv("SECRET_KEY"))
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# ✅ Optional: Fail fast if SECRET_KEY is missing

if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set. Please define it in your .env file.")

print("🔐 Loaded SECRET_KEY:", SECRET_KEY)
