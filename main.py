import datetime
import os
import uuid
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models import User, Role, Patient
from database import create_tables, get_db
from pydantic import BaseModel as PydanticBaseModel, field_validator
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

# Constants
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# FastAPI instance with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(lifespan=lifespan)

# Password Context for Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def parse_date_string(date_str: str) -> Optional[datetime.datetime]:
    if isinstance(date_str, str) and date_str.strip() != "":
        try:
            return datetime.datetime.strptime(date_str, "%d-%m-%Y")
        except ValueError:
            raise ValueError(f"Invalid date format. Expected 'DD-MM-YYYY'.")
    return None


def decode_jwt(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


class UserModel(PydanticBaseModel):
    name: str
    username: str
    password: str


class PatientModel(PydanticBaseModel):
    id: Optional[uuid.uuid4] = None
    name: str
    age: int
    picked_from: str
    dropped_at: str
    date: datetime.datetime
    amount: int
    driver: Optional[str]

    @field_validator("date", mode="before")
    @classmethod
    def parse_date(cls, value):
        return parse_date_string(value)


class PatientDetailsModel(PydanticBaseModel):
    name: Optional[str] = ""
    picked_from: Optional[str] = ""
    dropped_at: Optional[str] = ""
    from_date: Optional[datetime.datetime] = None
    to_date: Optional[datetime.datetime] = None
    date: Optional[datetime.datetime] = None

    @field_validator("date", "from_date", "to_date", mode="before")
    @classmethod
    def parse_date(cls, value):
        return parse_date_string(value)


class PatientUpdateModel(PydanticBaseModel):
    name: Optional[str] = ""
    picked_from: Optional[str] = ""
    dropped_at: Optional[str] = ""
    date: Optional[datetime.datetime] = None
    age: Optional[int] = None
    amount: Optional[int] = None
    driver: Optional[str] = None

    @field_validator("date", mode="before")
    @classmethod
    def parse_date(cls, value):
        return parse_date_string(value)


@app.get("/")
def homepage():
    return {"message": "Wel-Come"}


@app.post("/token")
def create_token(data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        user_exists = db.query(User).filter(data.username == User.username).first()
        if user_exists:
            if verify_password(data.password, user_exists.password):
                expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                jwt_token = jwt.encode(
                    {"username": user_exists.username, "role": user_exists.role.value, "exp": expiry},
                    SECRET_KEY, algorithm=ALGORITHM)
                return {"access_token": jwt_token, "token_type": "bearer"}
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


# @app.post("/login")
# def login(username: str, password: str, db: Session = Depends(get_db)):
#     user_exists = db.query(User).filter(username == User.username).first()
#     if user_exists:
#         if verify_password(password, user_exists.password):
#             expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#             jwt_token = jwt.encode({"username": user_exists.username, "role": user_exists.role.value, "exp": expiry},
#                                    SECRET_KEY, algorithm=ALGORITHM)
#             return {"access_token": jwt_token, "token_type": "bearer"}
#         else:
#             raise HTTPException(status_code=401, detail="Invalid password")
#     else:
#         return HTTPException(status_code=404, detail="User does not exist.")


@app.post("/register")
def register(user: UserModel, db: Session = Depends(get_db)):
    try:
        check_user = db.query(User).filter(user.username == User.username).all()
        if not check_user:
            new_user = User(name=user.name, username=user.username, password=pwd_context.hash(user.password))
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            return {"msg": f"user {user.username} is registered."}
        else:
            return HTTPException(status_code=409, detail="Username already exist")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/add-patient")
def add_patient(patient: PatientModel, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    try:
        new_patient = Patient(
            name=patient.name,
            age=patient.age,
            pickedfrom=patient.picked_from,
            droppedat=patient.dropped_at,
            date=patient.date,
            amount=patient.amount,
            driver=current_user["username"],
        )
        db.add(new_patient)
        db.commit()
        db.refresh(new_patient)
        return {f"Patient {patient.name} added."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/get-details")
def get_details(details: PatientDetailsModel, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    try:
        print(details)
        patient_details_query = None
        if current_user["role"] == "DRIVER":
            patient_details_query = db.query(Patient).filter(Patient.driver == str(current_user["username"]))
        if current_user["role"] == "OWNER":
            patient_details_query = db.query(Patient)

        if details.name:
            patient_details_query = patient_details_query.filter(Patient.name == details.name)
            print("name added", patient_details_query)
        if details.date:
            patient_details_query = patient_details_query.filter(Patient.date == details.date)
        if details.from_date:
            patient_details_query = patient_details_query.filter(Patient.date >= details.from_date)
        if details.to_date:
            patient_details_query = patient_details_query.filter(Patient.date <= details.to_date)
        if details.picked_from:
            patient_details_query = patient_details_query.filter(Patient.pickedfrom == details.picked_from)
        if details.dropped_at:
            patient_details_query = patient_details_query.filter(Patient.droppedat == details.dropped_at)
        return {"patient_details": patient_details_query.all()}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.patch("/update-patient")
def update_patient(patient_id: str, data_to_update: PatientUpdateModel, db: Session = Depends(get_db),
                   token: str = Depends(oauth2_scheme)):
    current_user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    try:
        patient_record = db.query(Patient).filter(
            Patient.id == patient_id and Patient.driver == str(current_user["username"])).first()
        if not patient_record:
            return HTTPException(status_code=404, detail=f"Patient{patient_id} does not exist.")
        if current_user["username"] != patient_record.driver and current_user["role"] != "OWNER":
            return HTTPException(status_code=403, detail=f"You dont have permission to edit Patient{patient_id}.")
        if data_to_update.name:
            patient_record.name = data_to_update.name
        if data_to_update.age:
            patient_record.age = data_to_update.age
        if data_to_update.picked_from:
            patient_record.picked_from = data_to_update.picked_from
        if data_to_update.dropped_at:
            patient_record.dropped_at = data_to_update.dropped_at
        if data_to_update.date:
            patient_record.date = data_to_update.date
        if data_to_update.amount:
            patient_record.amount = data_to_update.amount
        db.commit()
        db.refresh(patient_record)
        return {"updated record": patient_record}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")

# if __name__ == '__main__':
#
# def add_patient_data_from_file(file: str = None):
#     import json
#     import requests
#     if not file:
#         file = "C:\\Users\\ajaybhan\\Downloads\\patient_records_updated.json"
#
#     with open(file, "r") as fp:
#         patient_data = json.load(fp)
#         for data in patient_data:
#             driver = data["driver"]
#             response = requests.post(f'http://127.0.0.1:8000/login?username={driver}&password=12345')
#             if response:
#                 token = response.json()
#                 new_res = requests.post(url='http://127.0.0.1:8000/add-patient',
#                                         headers={
#                                             'accept': 'application/json',
#                                             'Authorization': f'{token["token_type"]} {token["access_token"]}',
#                                             'Content-Type': 'application/json'
#                                         },
#                                         json=data
#                                         )
#                 print(new_res.json())
#
# add_patient_data_from_file()
#
