import enum
import uuid
from sqlalchemy import Column, Integer, Text, ForeignKey, String, Enum, DateTime
from database import Base, create_tables
from sqlalchemy.orm import relationship


class Role(str, enum.Enum):
    OWNER = "OWNER"
    DRIVER = "DRIVER"


class User(Base):
    __tablename__ = "user"
    name = Column(String(50))
    username = Column(String(16), primary_key=True)
    password = Column(String(250))
    role = Column(Enum(Role), default=Role.DRIVER)

    patient = relationship("Patient", back_populates="user")


class Patient(Base):
    __tablename__ = "patient"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50))
    age = Column(Integer)
    pickedfrom = Column(String(80))
    droppedat = Column(String(80))
    amount = Column(Integer)
    date = Column(DateTime)
    driver = Column(String, ForeignKey("user.username"), nullable=False)

    user = relationship("User", back_populates="patient")
