import datetime
import os

import jwt
from dotenv import load_dotenv
from fastapi import HTTPException, status

load_dotenv()

# Constants
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def decode_jwt(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


def encode_jwt(user_exists):
    expiry = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jwt_token = jwt.encode(
        {"username": user_exists.username, "role": user_exists.role.value, "exp": expiry},
        SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": jwt_token, "token_type": "bearer"}

