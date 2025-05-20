import enum
from sqlalchemy import Column, String, Enum
from sqlalchemy.orm import relationship

from core.database import Base


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