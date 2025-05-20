from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from custom_utils.custom_logger import init_logger
from custom_utils.crypt_operations import verify_password, encrypt_password
from core.database import create_tables, get_db
from models.user import User as UserModel
from models.patient import Patient as PatientModel
from schemas.user import UserSchema
from schemas.patient import PatientSchema, PatientUpdate, PatientSearchCriteria
from sqlalchemy.orm import Session

from contextlib import asynccontextmanager
from custom_utils.jwt_operations import encode_jwt, decode_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
logger = log = init_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/")
def homepage():
    logger.info("Homepage accessed.")
    return {"message": "Wel-Come"}


@app.post("/token")
def create_token(data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logger.info(f"Token request for username: {data.username}")
    try:
        user_exists = db.query(UserModel).filter(data.username == UserModel.username).first()
        if user_exists:
            if verify_password(data.password, user_exists.password):
                logger.info(f"User {data.username} authenticated successfully.")
                return encode_jwt(user_exists)
            else:
                logger.warning(f"Invalid password attempt for user {data.username}.")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
        else:
            logger.warning(f"User {data.username} not found.")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error occurred during token creation: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/register")
def register(user: UserSchema, db: Session = Depends(get_db)):
    logger.info(f"Attempt to register user: {user.username}")
    try:
        check_user = db.query(UserModel).filter(user.username == UserModel.username).all()
        if not check_user:
            new_user = UserModel(name=user.name, username=user.username, password=encrypt_password(user.password))
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            logger.info(f"User {user.username} registered successfully.")
            return {"msg": f"user {user.username} is registered."}
        else:
            logger.warning(f"Username {user.username} already exists.")
            return HTTPException(status_code=409, detail="Username already exist")
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred during registration for user {user.username}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/add-patient")
def add_patient(patient: PatientSchema, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    current_user = decode_jwt(token)
    logger.info(f"User {current_user['username']} adding a patient.")
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
        logger.info(f"Patient {patient.name} added successfully by user {current_user['username']}.")
        return {f"Patient {patient.name} added."}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while adding patient {patient.name}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/get-search_criteria")
def get_search_criteria(search_criteria: PatientSearchCriteria, db: Session = Depends(get_db),
                        token: str = Depends(oauth2_scheme)):
    print(search_criteria)
    current_user = decode_jwt(token)
    logger.info(f"User {current_user['username']} requesting search criteria for patients.")
    try:
        patient_search_query = None
        if current_user["role"] == "DRIVER":
            patient_search_query = db.query(PatientModel).filter(str(current_user["username"]) == PatientModel.driver)
        if current_user["role"] == "OWNER":
            patient_search_query = db.query(PatientModel)

        search_criteria_dict = search_criteria.model_dump(exclude_unset=True)
        filtered_search = {field: value for field, value in search_criteria_dict.items() if value not in ["", None]}
        for field, value in filtered_search.items():
            if field == "from_date":
                patient_search_query = patient_search_query.filter(PatientModel.date >= value)
                continue
            if field == "to_date":
                patient_search_query = patient_search_query.filter(PatientModel.date <= value)
                continue
            patient_search_query = patient_search_query.filter(getattr(PatientModel, field) == value)

        logger.info(f"Search criteria applied successfully.")
        return {"patient_search_criteria": patient_search_query.all()}
    except Exception as e:
        logger.error(f"Error occurred while retrieving patient by search criteria: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.patch("/update-patient")
def update_patient(patient_id: str, data_to_update: PatientUpdate, db: Session = Depends(get_db),
                   token: str = Depends(oauth2_scheme)):
    current_user = decode_jwt(token)
    logger.info(f"User {current_user['username']} updating patient with ID {patient_id}.")
    try:
        patient_record = db.query(PatientModel).filter(
            PatientModel.id == patient_id and str(current_user["username"]) == PatientModel.driver).first()

        if not patient_record:
            logger.warning(f"Patient {patient_id} not found for update.")
            return HTTPException(status_code=404, detail=f"Patient {patient_id} does not exist.")
        if current_user["username"] != patient_record.driver and current_user["role"] != "OWNER":
            logger.warning(f"User {current_user['username']} does not have permission to update patient {patient_id}.")
            return HTTPException(status_code=403, detail=f"You don't have permission to edit Patient {patient_id}.")

        data_to_update_dict = data_to_update.model_dump(exclude_unset=True)
        filtered_data = {field: value for field, value in data_to_update_dict.items() if value not in [None, ""]}

        for field, value in filtered_data.items():
            patient_record = patient_record.filter(getattr(PatientModel, field) == value)

        db.commit()
        db.refresh(patient_record)
        logger.info(f"Patient {patient_id} updated successfully.")
        return {"updated record": patient_record}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while updating patient {patient_id}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")


@app.post("/delete/{patient_id}")
def delete_patient(patient_id: str, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = decode_jwt(token)
    logger.info(f"User {current_user['username']} attempting to delete patient with ID {patient_id}.")
    try:
        patient_record = db.query(PatientModel).filter(patient_id == PatientModel.id).first()
        if not patient_record:
            logger.warning(f"Patient {patient_id} not found for deletion.")
            return HTTPException(status_code=404, detail=f"Patient {patient_id} does not exist.")
        if current_user["username"] != patient_record.driver and current_user["role"] != "OWNER":
            logger.warning(f"User {current_user['username']} does not have permission to delete patient {patient_id}.")
            return HTTPException(status_code=403, detail=f"You don't have permission to delete Patient {patient_id}.")

        db.delete(patient_record)
        db.commit()
        logger.info(f"Patient {patient_id} deleted successfully.")
        return {"Record deleted: ": patient_record}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occurred while deleting patient {patient_id}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An error occurred: {str(e)}")
