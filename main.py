

from typing import List
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
import crud, models, schemas
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm


models.Base.metadata.create_all(bind=engine)

app = FastAPI()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# register user to end point
@app.post("/users/")
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    print("db_user", db_user)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


#login user endpoint
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(),db:Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db=db, username=form_data.username)
    if not db_user:
        raise HTTPException(status_code = 401,detail = "This username not found")
    
    if crud.verify_password(form_data.password,db_user.hashed_password):
        token = crud.create_access_token(db_user)
        return {"access_token":token,"token_type":"bearer"}
    raise HTTPException(status_code = 401,detail = "password not matched")
        
#get all user endpooints
@app.get("/users/",response_model=List[schemas.User],dependencies=[Depends(crud.check_admin)])
def read_users(skip:int = 0,limit: int = 100, db:Session = Depends(get_db)):
    print("reading all users")
    users = crud.get_users(db,skip = skip,limit = limit)
    return users


#get user by id endpoint
@app.get("/users/{user_id}", response_model=schemas.User, dependencies=[Depends(crud.check_admin)])
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


#create user item end point
@app.post("/users/{user_id}/pois/", response_model=schemas.POI,dependencies=[Depends(crud.check_admin)])
def create_poi_for_user(
    user_id: int, poi: schemas.POICreate, db: Session = Depends(get_db)
):
    return crud.create_user_poi(db=db, poi=poi, user_id=user_id)


#get user items end point
@app.get("/pois/", response_model=List[schemas.POI],dependencies=[Depends(crud.check_admin)])
def read_pois(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    pois = crud.get_pois(db, skip=skip, limit=limit)
    return pois

@app.patch("/users/{user_id}", response_model=schemas.User,dependencies=[Depends(crud.check_admin)])
def update_user_data(
    user_id: int, user_update: schemas.UserCreate, db: Session = Depends(get_db),
    current_user: schemas.User = Depends(crud.check_active)
):
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="You can only update your own data")
    return crud.update_user(db=db, user_id=user_id, user_update=user_update)

@app.delete("/users/{user_id}", response_model=schemas.User)
def delete_user_data(
    user_id: int, db: Session = Depends(get_db),
    current_user: schemas.User = Depends(crud.check_active)
):
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="You can only delete your own data")
    return crud.delete_user(db=db, user_id=user_id)

# Update POI by ID endpoint
@app.patch("/pois/{poi_id}", response_model=schemas.POI)
def update_poi_data(
    poi_id: int, poi_update: schemas.POICreate, db: Session = Depends(get_db),
    current_user: schemas.User = Depends(crud.check_active)
):
    db_poi = crud.get_poi_by_id(db=db, poi_id=poi_id)
    if db_poi.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only update your own POIs")
    return crud.update_poi(db=db, poi_id=poi_id, poi_update=poi_update)

@app.delete("/pois/{poi_id}", response_model=schemas.POI)
def delete_poi_data(
    poi_id: int, db: Session = Depends(get_db),
    current_user: schemas.User = Depends(crud.check_active)
):
    db_poi = crud.get_poi_by_id(db=db, poi_id=poi_id)
    if db_poi.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own POIs")
    return crud.delete_poi(db=db, poi_id=poi_id)

'''#update POI for user
@app.patch("/users/{user_id}/pois/{poi_id}", response_model=schemas.POI)
def update_user_poi(
    user_id: int, poi_id: int, poi_update: schemas.POICreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(crud.check_active)
):
    db_poi = crud.get_poi_by_id(db, poi_id=poi_id)
    if db_poi.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied. You can only update your own POI.")
    return crud.update_user_poi(db=db, poi_id=poi_id, poi_update=poi_update)

#delete POI for user
@app.delete("/users/{user_id}/pois/{poi_id}", response_model=schemas.POI)
def delete_user_poi(
    user_id: int, poi_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(crud.check_active)
):
    db_poi = crud.get_poi_by_id(db, poi_id=poi_id)
    if db_poi.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied. You can only delete your own POI.")
    return crud.delete_user_poi(db=db, poi_id=poi_id)

#admin can update any user's POI
@app.patch("/admin/users/{user_id}/pois/{poi_id}", response_model=schemas.POI)
def admin_update_user_poi(
    user_id: int, poi_id: int, poi_update: schemas.POICreate, db: Session = Depends(get_db), current_admin: schemas.User = Depends(crud.check_admin)
):
    return crud.update_user_poi(db=db, poi_id=poi_id, poi_update=poi_update)

#admin can delete any user's POI
@app.delete("/admin/users/{user_id}/pois/{poi_id}", response_model=schemas.POI)
def admin_delete_user_poi(
    user_id: int, poi_id: int, db: Session = Depends(get_db), current_admin: schemas.User = Depends(crud.check_admin)
):
    return crud.delete_user_poi(db=db, poi_id=poi_id)'''