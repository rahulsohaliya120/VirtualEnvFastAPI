from typing import Union
from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from schemas import UpdatePasswordRequest

import models, schemas, auth
from database import SessionLocal, engine
from emailer import send_verification_email
import uuid

# Create the database tables    
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title = "My First API", description = "This is a sample API", version = "1.0.0")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/signup")
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_pwd = auth.get_password_hash(user.password)
    token = auth.create_email_verification_token(data={"sub": user.email})
    new_user = models.User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_pwd,
        verification_token=token
    )
   
    access_token = auth.create_access_token(data={"sub": new_user.username})
    refresh_token = auth.create_refresh_token(data={"sub": new_user.username})

    send_verification_email(
        to_email=user.email,
        username=user.username,
        token=token)   

    token_entry = models.TokenBlacklist(token=access_token)
    db.add(token_entry)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {
        "message": "User created successfully",
        "user": schemas.UserResponse.from_orm(new_user),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "verification_token": token,
        "token_type": "bearer"
    }

@app.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    if not user.emailverified:
        raise HTTPException(status_code=403, detail="Email not verified.")

    # if not user or not auth.verify_password(form_data.password, user.hashed_password):
    #     raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = auth.create_access_token(data={"sub": user.username})
    refresh_token = auth.create_refresh_token(data={"sub": user.username})
    token_entry = models.TokenBlacklist(token=access_token)
    token = auth.create_email_verification_token(data={"sub": user.email})

    db.add(token_entry)
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "verification_token": token, "token_type": "bearer", "user": schemas.UserResponse.from_orm(user)}

@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    user.emailverified = True
    
    db.commit()
    return {"message": "Email verified successfully!"}

@app.post("/refresh-token", response_model=schemas.Token)
def refresh_token_endpoint(request: schemas.RefreshTokenRequest, db: Session = Depends(get_db)):
    try:
        payload = auth.decode_access_token(request.refresh_token, db)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # You can verify the user exists here too if needed
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        new_access_token = auth.create_access_token(data={"sub": username})
        new_refresh_token = auth.create_refresh_token(data={"sub": username})

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "user": schemas.UserResponse.from_orm(user)
        }

    except auth.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@app.get("/users/me", response_model=schemas.UserResponse)
def read_users_me(db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth.decode_access_token(token, db)
        username = str(payload.get("sub"))
        if username is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception

    return schemas.UserResponse.from_orm(user)

@app.get("/users/{user_id}", response_model=schemas.UserResponse)
def read_user(user_id: int, db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth.decode_access_token(token, db)
        username = str(payload.get("sub"))  # not recommended unless you're sure
        if username is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return schemas.UserResponse.from_orm(user)

@app.delete("/user/delete/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth.decode_access_token(token, db)
        username = str(payload.get("sub"))
        if username is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content={"message": "User deleted successfully"})

@app.put("/user/update/{user_id}", response_model=schemas.UserResponse)
def update_user(user_id: int, user: schemas.UserCreate, db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth.decode_access_token(token, db)
        username = str(payload.get("sub"))
        if username is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception

    existing_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    if db.query(models.User).filter(models.User.username == user.username, models.User.id != user_id).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    if db.query(models.User).filter(models.User.email == user.email, models.User.id != user_id).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    existing_user.username = user.username
    existing_user.email = user.email
    existing_user.full_name = user.full_name
    existing_user.hashed_password = auth.get_password_hash(user.password)

    db.commit()
    db.refresh(existing_user)
    
    return schemas.UserResponse.from_orm(existing_user)

@app.put("/user/updatepassword/{user_id}")
def update_password(
    user_id: int,
    password_data: UpdatePasswordRequest,
    db: Session = Depends(get_db),
    token: str = Depends(auth.oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth.decode_access_token(token, db)
        username = str(payload.get("sub"))
        if username is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = auth.get_password_hash(password_data.password)
    db.commit()
    db.refresh(user)

    return {"message": "Password updated successfully"}

@app.get("/user/logout", status_code=status.HTTP_200_OK)
def logout(token: str = Depends(auth.oauth2_scheme), db: Session = Depends(get_db)):
    db_token = db.query(models.TokenBlacklist).filter(models.TokenBlacklist.token == token).first()
    if db_token:
        db.delete(db_token)
        db.commit()
        return {"message": "Logged out successfully"}
    raise HTTPException(status_code=401, detail="Invalid or already logged out token")
