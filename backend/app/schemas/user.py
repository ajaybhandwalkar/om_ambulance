from pydantic import BaseModel as PydanticBaseModel


class UserSchema(PydanticBaseModel):
    name: str
    username: str
    password: str
