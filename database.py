

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

#SQLALCHEMY_DATABASE_URL = 'sqlite:///your_database.db'
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:admin@localhost:5433/TIK"

# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

'''engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)'''
#engine = create_engine(SQLALCHEMY_DATABASE_URL,echo = True, connect_args={"check_same_thread": False})
engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

#with engine.connect() as connection:
#    connection.execute("SELECT load_extension('mod_spatialite');")
# = databases.Database(SQLALCHEMY_DATABASE_URL)
