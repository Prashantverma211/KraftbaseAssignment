import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

load_dotenv()


# URLTODB=os.getenv('URLTODB')

# print(URLTODB)
#hardcoding
URLTODB="postgresql://postgres:password@localhost:5432/AssignmentKraft"


if URLTODB is None:
    raise ValueError("The environment variable 'URLTODB' is not set.")

engine = create_engine(URLTODB)
Session_local= sessionmaker(autocommit=False,autoflush=False,bind=engine)
Base=declarative_base()