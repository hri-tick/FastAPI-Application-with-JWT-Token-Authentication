
from sqlalchemy.orm import Session
import models, schemas
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
import crud

JWT_SECRET = "hritik"
ALGORITHM = "HS256"
from datetime import datetime, timedelta

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    hash_pass = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hash_pass, username=user.username, is_active=user.is_active, role = user.role)
    token = crud.create_access_token(db_user)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"db_user": db_user, "token": token}

def get_pois(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.POI).offset(skip).limit(limit).all()


def create_user_poi(db: Session, poi: schemas.POICreate, user_id: int):
    db_item = models.POI(name = poi.name ,geometry = poi.geometry, owner_id=user_id)
    
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def create_access_token(user):
    print("user", user.email)
    try:
        claims = {
            "id": user.id,
            "role" : user.role,
            "email": user.email,
            "username": user.username,
            "is_active": user.is_active,
            "password": user.hashed_password,
            "exp": datetime.utcnow() + timedelta(minutes=45),
        }
        return jwt.encode(claims=claims, key=JWT_SECRET, algorithm=ALGORITHM)
    except Exception as ex:
        print(str(ex))
        raise ex

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

def verify_token(token):
    try:
        payload = jwt.decode(token, key=JWT_SECRET)
        print("1----------")
        return payload
    except:
        print("2----------")
        raise Exception("Wrong token")

def check_active(token: str = Depends(oauth2_scheme)):
    print("abc")
    payload = verify_token(token)
    active = payload.get("is_active")
    print("3----------")
    if not active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please activate your Account first",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        return payload
    
    
def check_admin(payload:str = Depends(check_active)):
    print("payload",payload)
    role = payload.get("role")
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this is only accesable by admin",
        )
    else:
        return payload
    
    
def get_poi_by_id(db: Session, poi_id: int):
    return db.query(models.POI).filter(models.POI.id == poi_id).first()



def update_user(db: Session, user_id: int, user_update: schemas.UserCreate):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        for key, value in user_update.dict().items():
            setattr(db_user, key, value)
        db.commit()
        db.refresh(db_user)
        return db_user
    else:
        raise HTTPException(status_code=404, detail="User not found")

def delete_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db.delete(db_user)
        db.commit()
        return db_user
    else:
        raise HTTPException(status_code=404, detail="User not found")
        
def update_poi(db: Session, poi_id: int, poi_update: schemas.POICreate):
    db_poi = db.query(models.POI).filter(models.POI.id == poi_id).first()
    if db_poi:
        for key, value in poi_update.dict().items():
            setattr(db_poi, key, value)
        db.commit()
        db.refresh(db_poi)
        return db_poi
    else:
        raise HTTPException(status_code=404, detail="POI not found")

def delete_poi(db: Session, poi_id: int):
    db_poi = db.query(models.POI).filter(models.POI.id == poi_id).first()
    if db_poi:
        db.delete(db_poi)
        db.commit()
        return db_poi
    else:
        raise HTTPException(status_code=404, detail="POI not found")

'''def update_user_poi(db: Session, poi_id: int, poi_update: schemas.POICreate):
    db_poi = get_poi_by_id(db, poi_id=poi_id)
    if db_poi:
        for key, value in poi_update.dict().items():
            setattr(db_poi, key, value)
        db.commit()
        db.refresh(db_poi)
    return db_poi

def delete_user_poi(db: Session, poi_id: int):
    db_poi = get_poi_by_id(db, poi_id=poi_id)
    if db_poi:
        db.delete(db_poi)
        db.commit()
    return db_poi'''