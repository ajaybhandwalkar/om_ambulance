from pydantic import BaseModel, field_validator
from typing import Optional
import uuid
import datetime

from custom_utils.custom_logger import init_logger

logger = log = init_logger()

def parse_date_string(date_str: str) -> Optional[datetime.datetime]:
    if isinstance(date_str, str) and date_str.strip() != "" and len(date_str)>=10:
        try:
            logger.info(date_str)
            try:
                return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M").date()
            except ValueError:
                return datetime.datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            logger.warning(f"Invalid date format. Expected 'YYYY-MM-DD'. Trying for DD-MM-YYYY")
            try:
                return datetime.datetime.strptime(date_str, "%d-%m-%Y")
            except:
                raise ValueError(f"Invalid date format {date_str}")
    return None


class PatientSchema(BaseModel):
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


class PatientCommonFields(BaseModel):
    name: Optional[str] = ""
    picked_from: Optional[str] = ""
    dropped_at: Optional[str] = ""
    date: Optional[datetime.datetime] = None


class PatientSearchCriteria(PatientCommonFields):
    from_date: Optional[datetime.datetime] = None
    to_date: Optional[datetime.datetime] = None
    driver: Optional[str] = ""

    @field_validator("date", "from_date", "to_date", mode="before")
    @classmethod
    def parse_date(cls, value):
        return parse_date_string(value)


class PatientUpdate(PatientCommonFields):
    age: Optional[int] = None
    amount: Optional[int] = None
    driver: Optional[str] = None

    @field_validator("date", mode="before")
    @classmethod
    def parse_date(cls, value):
        return parse_date_string(value)
