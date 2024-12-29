from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

URLTODB = 'postgresql://postgres:password@localhost:5432/AssignmentKraft'
# URLTODB = 'postgresql://AssignmentKraft_owner:w5EejPk0QbVO@ep-patient-tree-a5gl691c.us-east-2.aws.neon.tech/AssignmentKraft'


engine = create_engine(URLTODB)
Session_local= sessionmaker(autocommit=False,autoflush=False,bind=engine)
Base=declarative_base()