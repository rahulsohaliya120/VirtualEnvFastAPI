from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    emailverified: bool

    
    class Config:
        from_attributes = True

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenRequest(BaseModel):
    token: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: UserResponse

    class Config:
        from_attributes = True

class UpdatePasswordRequest(BaseModel):
    password: str

    class Config:
        from_attributes = True