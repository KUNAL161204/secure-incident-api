import os
import jwt
import datetime
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from dotenv import load_dotenv
import models
import schemas

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Setup the password hashing engine
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def create_user(db: Session, user: schemas.UserCreate):
    # 1. Hash the password
    hashed_password = get_password_hash(user.password)
    
    # 2. Create the database object
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    
    # 3. Save it to the database
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    # The token will expire in 30 minutes
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode.update({"exp": expire})
    
    # Create the cryptographically signed token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_incident(db: Session, incident: schemas.IncidentCreate, user_id: int):
    # Create the database object, tying it to the user who submitted it
    db_incident = models.Incident(
        title=incident.title,
        description=incident.description,
        reporter_id=user_id
    )
    
    # Save to the database
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    
    return db_incident

def get_user_incidents(db: Session, user_id: int):
    # Fetch only incidents where reporter_id matches the logged-in user
    return db.query(models.Incident).filter(models.Incident.reporter_id == user_id).all()

def get_all_incidents(db: Session):
    # Fetch absolutely everything (For Admins only)
    return db.query(models.Incident).all()

def create_audit_log(db: Session, action_type: str, user_id: int):
    # Silently record what the user just did
    db_log = models.AuditLog(action_type=action_type, user_id=user_id)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_audit_logs(db: Session):
    # Only for admins
    return db.query(models.AuditLog).all()