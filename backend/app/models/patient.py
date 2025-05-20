import uuid
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime
from core.database import Base
from sqlalchemy.orm import relationship


class Patient(Base):
    __tablename__ = "patient"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50))
    age = Column(Integer)
    picked_from = Column(String(80))
    dropped_at = Column(String(80))
    amount = Column(Integer)
    date = Column(DateTime)
    driver = Column(String, ForeignKey("user.username"), nullable=False)

    user = relationship("User", back_populates="patient")