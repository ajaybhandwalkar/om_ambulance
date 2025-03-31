import datetime
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models import User, Role, Patient
from database import create_tables, get_db
from pydantic import BaseModel as PydanticBaseModel, field_validator
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(lifespan=lifespan)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = '1cfbaa0e20a5450894beaee820cca556'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class UserModel(PydanticBaseModel):
    name: str
    username: str
    password: str


class PatientModel(PydanticBaseModel):
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
        if isinstance(value, str):
            return datetime.datetime.strptime(value, "%d-%m-%Y")
        return value


class DetailsModel(PydanticBaseModel):
    name: Optional[str] = ""
    picked_from: Optional[str] = ""
    dropped_at: Optional[str] = ""
    from_date: Optional[datetime.datetime] = None
    to_date: Optional[datetime.datetime] = None
    date: Optional[datetime.datetime] = None

    @field_validator("date", mode="before")
    @field_validator("from_date", mode="before")
    @field_validator("to_date", mode="before")
    @classmethod
    def parse_date(cls, value):
        if isinstance(value, str):
            return datetime.datetime.strptime(value, "%d-%m-%Y")
        return value


@app.get("/")
def homepage():
    return {"message": "Wel-Come"}


@app.post("/token")
def create_token(data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    print(data.username)
    user = db.query(User).filter(User.username == data.username and User.password == data.password).one()
    if user:
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        token = jwt.encode({"username": user.username, "role": user.role.value, "exp": expires}, SECRET_KEY,
                           algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}


@app.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user_exists = db.query(User).filter(username == User.username).one()
    if user_exists:
        if verify_password(password, user_exists.password):
            expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            jwt_token = jwt.encode({"username": user_exists.username, "role": user_exists.role.value, "exp": expiry},
                                   SECRET_KEY, algorithm=ALGORITHM)
            return {"access_token": jwt_token, "token_type": "bearer"}
        else:
            raise HTTPException(status_code=401, detail="Invalid password")
    else:
        return HTTPException(status_code=404, detail="User does not exist.")


@app.post("/register")
def register(user: UserModel, db: Session = Depends(get_db)):
    check_user = db.query(User).filter(user.username == User.username).all()
    if not check_user:
        new_user = User(name=user.name, username=user.username, password=get_password_hash(user.password))
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"msg": f"user {user.username} is registered."}
    else:
        return HTTPException(status_code=409, detail="Username already exist")


@app.post("/add-patient")
def add_patient(patient: PatientModel, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    print(patient)
    new_patient = Patient(
        name=patient.name,
        age=patient.age,
        pickedfrom=patient.picked_from,
        droppedat=patient.dropped_at,
        date=patient.date,
        amount=patient.amount,
        driver=payload["username"],
    )
    db.add(new_patient)
    db.commit()
    db.refresh(new_patient)
    return {f"Patient {patient.name} added."}


@app.post("/get-details")
def get_details(details: DetailsModel, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    print(details)
    patient_details_query = None
    if payload["role"] == "DRIVER":
        patient_details_query = db.query(Patient).filter(Patient.driver == str(payload["username"]))
    if payload["role"] == "OWNER":
        patient_details_query = db.query(Patient)

    if details.name:
        patient_details_query = patient_details_query.filter(Patient.name == details.name)
        print("name added", patient_details_query)
    if details.date:
        patient_details_query = patient_details_query.filter(Patient.date == details.date)
    if details.from_date:
        patient_details_query = patient_details_query.filter(Patient.date <= details.date)
    if details.to_date:
        patient_details_query = patient_details_query.filter(Patient.date >= details.date)
    if details.picked_from:
        patient_details_query = patient_details_query.filter(Patient.pickedfrom == details.picked_from)
    if details.dropped_at:
        patient_details_query = patient_details_query.filter(Patient.droppedat == details.dropped_at)

    return {"patient_details": patient_details_query.all()}




def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


if __name__ == '__main__':

    def add_patient_data_from_file(file: str = None):
        import json
        import requests
        if not file:
            file = "C:\\Users\\ajaybhan\\Downloads\\patient_records_updated.json"

        with open(file, "r") as fp:
            patient_data = json.load(fp)
            for data in patient_data:
                driver = data["driver"]
                response = requests.post(f'http://127.0.0.1:8000/login?username={driver}&password=12345')
                if response:
                    token = response.json()
                    new_res = requests.post(url='http://127.0.0.1:8000/add-patient',
                                            headers={
                                                'accept': 'application/json',
                                                'Authorization': f'{token["token_type"]} {token["access_token"]}',
                                                'Content-Type': 'application/json'
                                            },
                                            json=data
                                            )
                    print(new_res.json())

    # add_patient_data_from_file()
