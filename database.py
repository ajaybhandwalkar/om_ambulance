from contextlib import contextmanager

from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine
from dotenv import load_dotenv
import os

load_dotenv()

Base = declarative_base()

database_url = os.getenv("DATABASE_URL")
engine = create_engine(database_url)
local_session = sessionmaker(autoflush=False, autocommit=False, bind=engine)


def create_tables():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = local_session()
    try:
        yield db
    finally:
        db.close()
