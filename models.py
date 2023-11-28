
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Float
from sqlalchemy.orm import relationship
from schemas import Roles
from sqlalchemy import Enum , text
from database import Base,engine
from geoalchemy2 import Geometry



class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    username = Column(String, unique=True)
    role = Column(Enum(Roles), default = "user")
    
    pois = relationship("POI", back_populates="owner")


class POI(Base):
    __tablename__ = "pois"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    geometry = Column(Geometry('POINT'))
    #geometry = Column(String, index=True)
    #geometry = Column(Geometry(geometry_type='POINT', srid=4326, spatial_index=True))
    #latitude = Column(Float)
    #longitude = Column(Float)
    

    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="pois")
    
    
#Base.metadata.create_all(bind=engine)
