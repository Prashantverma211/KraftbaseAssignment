from datetime import datetime, timezone
from typing import List, Union,Annotated

from fastapi.security import OAuth2PasswordBearer
from checkingRoute import checkingRoute
from pydantic import BaseModel
import models.models
from DB_Link.database import engine, Session_local
from sqlalchemy.orm import Session
import secrets

from fastapi import FastAPI,Depends,HTTPException, Query

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
models.models.Base.metadata.create_all(bind=engine)

class choiceBase(BaseModel):
    choice_text:str
    is_correct:bool
    
class questionBase(BaseModel):
    ques_text:str
    options:list[choiceBase]  

class UserBase(BaseModel):
    user_name:str
    email:str
    password:str
    
class LoginBase(BaseModel):
    email: str
    password: str
        
class FieldBase(BaseModel):
    field_id: str
    type: str
    label: str
    required: bool

class FormBase(BaseModel):
    title: str
    description: str
    fields: List[FieldBase]

    class Config:
        orm_mode = True

class ResponseToForm(BaseModel):
    field_id: str
    value: Union[str, int, bool]
    
class SubmitFormBase(BaseModel):
    responses:List[ResponseToForm]             
        
app.include_router(checkingRoute.router)

def get_db():
    db= Session_local()
    try:
        yield db
    finally:
        db.close()
        
dp_dependency = Annotated[Session, Depends(get_db)]

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def generate_session_token():
    return secrets.token_hex(32)

async def check_user_from_session(session_token: str, db: dp_dependency):
    session = db.query(models.models.Session).filter(models.models.Session.session_token == session_token).first()
    
    if not session:
        raise HTTPException(status_code=401, detail="Not authorised")
    
    user = db.query(models.models.Users).filter(models.models.Users.id == session.user_id).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found for session")
    print('passed from auth')
    return user


@app.post("/questions")
async def create_questions(question:questionBase, db:dp_dependency):
    db_ques=models.models.Questions(question_text=question.ques_text)
    db.add(db_ques)
    db.commit()
    db.refresh(db_ques)
    for choice in question.options :
        db_choice = models.models.Choices(question_id=db_ques.id,choice_text=choice.choice_text,is_correct=choice.is_correct)
        db.add(db_choice)
    db.commit()

@app.get("/question/{question_id}")
async def get_questionbyid(questionId:int, db:dp_dependency):
    result=db.query(models.models.Questions).filter(models.models.Questions.id==questionId).first()
    if not result:
       raise HTTPException(status_code=404,detail='Question not found')
    return result 
                   
@app.get("/choices/{question_id}")
async def get_choicesbyquestionid(questionId:int,db:dp_dependency):
    result=db.query(models.models.Choices).filter(models.models.Choices.question_id==questionId).all()
    if not result:
        raise HTTPException(status_code=404,detail='question does not exist')
    return result
                      
@app.post("/auth/register")
async def registerUser(UserData:UserBase, db:dp_dependency):
    duplicateEmail=db.query(models.models.Users).filter(models.models.Users.email==UserData.email).first()
    duplicateUserName=db.query(models.models.Users).filter(models.models.Users.username==UserData.user_name).first()
    if duplicateEmail or duplicateUserName:
        raise HTTPException(status_code=400,detail='User with same name/email already exists')
    passwordHash=hash_password(UserData.password)
    db_user=models.models.Users(username=UserData.user_name,email=UserData.email,password_hash=passwordHash)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {
        "message": "User successfully registered",
        "user": {
            "username": db_user.username,
            "email": db_user.email
        }
    }

@app.post("/auth/login")
async def login_user(loginData: LoginBase, db: dp_dependency):
    userFetched = db.query(models.models.Users).filter(models.models.Users.email == loginData.email).first()
    
    if not userFetched:
        raise HTTPException(status_code=401, detail="User Not Registered with this email")

    if not verify_password(loginData.password,userFetched.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    session_token = generate_session_token()
    
    new_session = models.models.Session(user_id=userFetched.id, session_token=session_token)
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    
    return {"message": "Login successful", "session_token": session_token}                       

@app.post("/auth/logout")
async def logout_user(session_token: str, db: dp_dependency):
    session = db.query(models.models.Session).filter(models.models.Session.session_token == session_token).first()

    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")

    db.delete(session)
    db.commit()

    return {"message": "Successfully logged out"}

@app.post("/create-form/")
async def create_form(form: FormBase,db:dp_dependency, token: str = Depends(oauth2_scheme)):
    await check_user_from_session(token, db)
    
    db_form = models.models.Form(title=form.title,description=form.description)
    
    db.add(db_form)
    db.commit()
    db.refresh(db_form)
    

    for field in form.fields:
        db_field = models.models.Field(
            field_id=field.field_id,
            type=field.type,
            label=field.label,
            required=field.required,
            form_id=db_form.id
        )
        db.add(db_field)

    db.commit()

    return {"message": "Form created successfully", "form_id": db_form.id}

@app.delete("/forms/delete/{form_id}")
async def delete_form(form_id: int, db: dp_dependency, token: str = Depends(oauth2_scheme)):
    await check_user_from_session(token, db)

    db_form = db.query(models.models.Form).filter(models.models.Form.id == form_id).first()

    if not db_form:
        raise HTTPException(status_code=404, detail="Form not found")

    for field in db_form.fields:
        db.delete(field)

    db.delete(db_form)
    
    db.commit()

    return {"message": "Form and associated fields deleted successfully"}


@app.get('/forms/')
async def getAllForms(db: dp_dependency, token: str = Depends(oauth2_scheme)):
    await check_user_from_session(token,db)
    result=db.query(models.models.Form).all()
    return result

@app.get('/forms/{form_id}')
async def getFormById(form_id:int,db: dp_dependency, token: str = Depends(oauth2_scheme)):
    await check_user_from_session(token,db)
    result=db.query(models.models.Form).filter(models.models.Form.id==form_id).first()
    
    if not result:
        raise HTTPException(status_code=404,detail='Form not found')
    
    return result

# @app.post("/forms/submit/{form_id}")
# async def submitForm(form_id:int,db:dp_dependency,SubmitData:SubmitFormBase):
#     formExist=db.query(models.models.Form).filter(models.models.Form.id==form_id).first()
#     if not formExist:
#         raise HTTPException(status_code=404,detail="Form you tryig to submit does nont exist")
#     AllFields=db.query(models.models.Field).filter(models.models.Field.form_id==form_id).all()
#     dataHash={}
#     for response in SubmitData.responses:
#         dataHash[response.field_id]=response.value
#     print(dataHash)    
#     for field in AllFields:  
#         if field.required and (not dataHash.get(str(field.id))):
#             raise HTTPException(status_code=400, detail=f"Field '{field.label}' is required.")
#         if dataHash.get(str(field.id)):
#             if (dataHash[field.id]=="True" or dataHash[field.id]=="False") and type(dataHash[field.id])!=bool:
#                 raise HTTPException(status_code=400,detail="Please fill correct type of data in respective field")
#             if(type(dataHash[field.id])!=field.type):
#                 raise HTTPException(status_code=400,detail="Please fill correct type of data in respective field")    
#     db_submit=models.models.Submission(submitted_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),data=dataHash,form_id=form_id)
#     db.add(db_submit)
#     db.commit()
#     return {"form submitted successfully"}

@app.post("/forms/submit/{form_id}")
async def submitForm(form_id: int, db: dp_dependency, SubmitData: SubmitFormBase):
    # Check if the form exists
    formExist = db.query(models.models.Form).filter(models.models.Form.id == form_id).first()
    if not formExist:
        raise HTTPException(status_code=404, detail="The form you are trying to submit does not exist")
    
    # Fetch all fields associated with the form
    allFields = db.query(models.models.Field).filter(models.models.Field.form_id == form_id).all()
    
    # Prepare the data dictionary from the responses
    dataHash = {str(response.field_id): response.value for response in SubmitData.responses}
    
    # Map string types to actual Python types
    type_mapping = {
        "text": str,
        "number": int,
        "boolean": bool,
        
    }
    
    # Validate required fields and their types
    for field in allFields:
        field_value = dataHash.get(str(field.field_id))  # Use .get() to avoid KeyError

        # Check if the required field is missing
        if field.required and not field_value:
            raise HTTPException(status_code=400, detail=f"Field '{field.label}' is required.")
        
        # If there's a value for the field, perform type validation
        if field_value is not None:
            # If the value is a string representing a boolean, convert it
            if isinstance(field_value, str) and field_value.lower() in ("true", "false"):
                field_value = field_value.lower() == "true"
            
            # Get the expected Python type
            expected_type = type_mapping.get(field.type)
            
            # Check if the expected type is valid and type matches
            if expected_type and not isinstance(field_value, expected_type):
                raise HTTPException(status_code=400, detail=f"Field '{field.label}' expects a value of type '{expected_type.__name__}'.")

    # Create the submission
    db_submit = models.models.Submission(
        submitted_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        data=dataHash,
        form_id=form_id
    )
    
    # Add the submission to the database
    db.add(db_submit)
    db.commit()

    return {"message": "Form submitted successfully"}


@app.get('/forms/submissions/{form_id}')
async def getFormSubmissions(form_id: int, db: dp_dependency, page :int = Query(1, ge=1), limit:int = Query(10, le=100)):
    print("hiiii")
    offset = (page - 1) * limit
    print(page,limit)
    
    totalCountOfSubmissions = db.query(models.models.Submission).filter(models.models.Submission.form_id == form_id).count()
    
    submissions = db.query(models.models.Submission).filter(models.models.Submission.form_id == form_id).offset(offset).limit(limit).all()

    result = []
    for submission in submissions:
        result.append({
            "submission_id": submission.id,
            "submitted_at": submission.submitted_at,
            "data": submission.data
        })
    
    return {
        "total_count": totalCountOfSubmissions,
        "page": page,
        "limit": limit,
        "submissions": result
    }