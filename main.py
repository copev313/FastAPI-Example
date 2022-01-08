"""
This module will house the entirety of this sample project.

=== E.Cope | January 2022 ===
"""
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },

    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

# ----------------------------------------------------------------------------

app = FastAPI()
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

# ----------------------------------------------------------------------------

class User(BaseModel):
    """An example basic user model for demonstrating authentication. """
    username: str
    email: EmailStr | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    """An extension model of User, used to simulate storing the user in
    a database. """
    hashed_password: str


def get_user(db, username: str):
    """Retrieves the user from the fake database. """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_hash_password(password: str):
    """Fake password hashing function. """
    return "fakehashed" + password

def fake_decode_token(token: str):
    """A fake token decoder function, in reality this would be using some
    implementation of JWT. """
    user = get_user(fake_users_db, token)
    return user

async def get_current_user(token: str = Depends(oauth2)):
    """Retrieves the current user based on the token provided. """
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid authentication credentials",
                            headers={"WWW-Authenticate": "Bearer"})
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
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Handles the login process. """
    user_dict = fake_users_db.get(form_data.username)
    # [CHECK] Check if the user exists in fake DB:
    if not user_dict:
        raise HTTPException(status_code=400,
                            detail="Incorrect username or password")
    
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    # [CHECK] Fake password hashes match.
    if not user.hashed_password == hashed_password:
        raise HTTPException(status_code=400,
                            detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}

# ----------------------------------------------------------------------------

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/users/me")
async def read_users_me(current_user: 
                            User = Depends(get_current_active_user)):
    return current_user
