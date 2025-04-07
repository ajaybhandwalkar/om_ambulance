import uuid
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime
from core.database import Base
from sqlalchemy.orm import relationship


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