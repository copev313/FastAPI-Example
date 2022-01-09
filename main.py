"""
This module will house the entirety of this sample project.

=== E.Cope | January 2022 ===
"""
from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:8080",
    "http://127.0.0.1:8000/"
]

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": 
            "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    """Represents a JWT token. """
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Represents the data in a JWT token. """
    username: str | None = None


class User(BaseModel):
    """A basic user model for demonstrating authentication. """
    username: str
    email: EmailStr | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    """Used to simulate storing a user's password hash in a database. """
    hashed_password: str

# ----------------------------------------------------------------------------

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2 = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------------------------------------------------------------------

def get_user(db, username: str):
    """Retrieves the user from the fake database. """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def get_password_hash(password: str):
    """Generates a hash of the password. """
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """Verifies a password against a hash. """
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(fake_db, username: str, password: str):
    """Authenticates a user. """
    user = get_user(fake_db, username)
    if user and verify_password(password, user.hashed_password):
        return user
    return False

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Creates an access token. """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(claims=to_encode,
                             key=SECRET_KEY,
                             algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2)):
    """Retrieves the current user based on the token provided. """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception

    return user

async def get_current_active_user(current_user: 
                                    User = Depends(get_current_user)):
    """Validates that the current user is active. """
    if current_user.disabled:
        raise HTTPException(status_code=400,
                            detail="Inactive user")
    return current_user

# ----------------------------------------------------------------------------

@app.post("/token")
async def login_for_access_token(form_data: 
                                    OAuth2PasswordRequestForm = Depends()):
    """Handles the login token process. """
    user = authenticate_user(fake_users_db, form_data.username,
                             form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ----------------------------------------------------------------------------

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/users/me")
async def read_users_me(current_user: 
                            User = Depends(get_current_active_user)):
    return current_user
