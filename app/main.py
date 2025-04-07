from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from utils.crypt_operations import verify_password, encrypt_password
from core.database import create_tables, get_db
from models.user import User as UserModel
from models.patient import Patient as PatientModel
from schemas.user import UserSchema
from schemas.patient import PatientSchema, PatientUpdate, PatientSearchCriteria
from sqlalchemy.orm import Session

from contextlib import asynccontextmanager
from utils.jwt_operations import encode_jwt, decode_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/")
def homepage():
    return {"message": "Wel-Come"}


@app.post("/token")
def create_token(data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        user_exists = db.query(UserModel).filter(data.username == UserModel.username).first()
        if user_exists:
            if verify_password(data.password, user_exists.password):
                return encode_jwt(user_exists)
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/register")
def register(user: UserSchema, db: Session = Depends(get_db)):
    try:
        check_user = db.query(UserModel).filter(user.username == UserModel.username).all()
        if not check_user:
            new_user = UserModel(name=user.name, username=user.username, password=encrypt_password(user.password))
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
def add_patient(patient: PatientSchema, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = decode_jwt(token)
    try:
        new_patient = PatientModel(
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


@app.post("/get-search_criteria")
def get_search_criteria(search_criteria: PatientSearchCriteria, db: Session = Depends(get_db),
                        token: str = Depends(oauth2_scheme)):
    current_user = decode_jwt(token)
    try:
        patient_search_query = None
        if current_user["role"] == "DRIVER":
            patient_search_query = db.query(PatientModel).filter(PatientModel.driver == str(current_user["username"]))
        if current_user["role"] == "OWNER":
            patient_search_query = db.query(PatientModel)

        search_criteria_dict = search_criteria.dict(exclude_unset=True)
        filtered_search = {field: value for field, value in search_criteria_dict.items() if value not in ["", None]}

        for field, value in filtered_search.items():
            setattr(patient_search_query, field, value)

        return {"patient_search_criteria": patient_search_query.all()}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.patch("/update-patient")
def update_patient(patient_id: str, data_to_update: PatientUpdate, db: Session = Depends(get_db),
                   token: str = Depends(oauth2_scheme)):
    current_user = decode_jwt(token)
    try:
        patient_record = db.query(PatientModel).filter(
            PatientModel.id == patient_id and PatientModel.driver == str(current_user["username"])).first()

        if not patient_record:
            return HTTPException(status_code=404, detail=f"Patient{patient_id} does not exist.")
        if current_user["username"] != patient_record.driver and current_user["role"] != "OWNER":
            return HTTPException(status_code=403, detail=f"You dont have permission to edit Patient{patient_id}.")

        data_to_update_dict = data_to_update.dict(exclude_unset=True)
        filtered_data = {field: value for field, value in data_to_update_dict.items() if value not in [None, ""]}

        for field, value in filtered_data.items():
            setattr(patient_record, field, value)

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
