
from typing import List, Union
from pydantic import BaseModel
from pydantic import BaseModel,EmailStr
from enum import Enum

class Roles(str, Enum):
    user = "user"
    admin = "admin"

        
class POIBase(BaseModel):
    name: str
    # if not description, then default None value added
    geometry: Union[str, None] = None 


class POICreate(POIBase):
    pass


class POI(POIBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True

class UserBase(BaseModel):
    username: str
    is_active: bool
    email: str
    role : Roles = "user"

class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool
    pois: List[POI] = []

    class Config:
        orm_mode = True
        
