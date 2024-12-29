import datetime
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String 
from models.session import Base
from sqlalchemy.orm import relationship
      
      
class Users(Base):
    __tablename__='users'
    
    id=Column(Integer, primary_key=True, index=True)
    username=Column(String,unique=True)
    email=Column(String,unique=True)
    password_hash = Column(String)
    
    sessions = relationship('Session', back_populates='user')
         
class Session(Base):
    __tablename__ = 'sessions'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    session_token = Column(String, unique=True)
    user = relationship('Users', back_populates='sessions')     
    
    
class Form(Base):
    __tablename__ = "forms"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)

    fields = relationship("Field", back_populates="form", cascade="all, delete-orphan")
    submissions = relationship("Submission", back_populates="form", cascade="all, delete-orphan")          
    
    
class Field(Base):
    __tablename__ = "fields"

    id = Column(Integer, primary_key=True, index=True)
    field_id = Column(String, nullable=False) 
    type = Column(String)
    label = Column(String)
    required = Column(Boolean)

    form_id = Column(Integer, ForeignKey("forms.id"))
    form = relationship("Form", back_populates="fields")
    
class Submission(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, index=True)
    submitted_at = Column(DateTime, default=datetime.datetime.utcnow)
    data = Column(JSON)  # To store the responses in a dictionary-like format
    
    form_id = Column(Integer, ForeignKey("forms.id"))
    form = relationship("Form", back_populates="submissions")
    
