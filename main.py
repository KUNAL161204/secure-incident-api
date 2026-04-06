from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware # NEW IMPORT
from fastapi.responses import FileResponse # NEW IMPORT
from sqlalchemy.orm import Session
import jwt
# ... rest of your imports
import models
import schemas
import crud
from database import engine, SessionLocal

# Connect to database and create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Incident Reporting API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows any frontend to connect (we will restrict this later when deploying)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# Dependency: This opens a database connection for a request, then closes it safely.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token using the secret key from crud.py
        payload = jwt.decode(token, crud.SECRET_KEY, algorithms=[crud.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    # Find the user in the database
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# The Elite Bouncer: First checks if you are logged in, THEN checks if you are an admin
def get_current_admin(current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You do not have permission to view this."
        )
    return current_user

# Replace the old root route with this:
@app.get("/", response_class=FileResponse)
def serve_frontend():
    # This tells FastAPI to load our beautiful HTML file when people visit the main URL
    return "index.html"

# 👑 ADMIN ROUTE: Provision a new user account
@app.post("/users/", response_model=schemas.UserResponse)
def register_user(
    user: schemas.UserCreate, 
    db: Session = Depends(get_db),
    current_admin: models.User = Depends(get_current_admin) # <-- THIS IS THE SHIELD
):
    # Check if a user with this email already exists
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create the new user using our crud function
    return crud.create_user(db=db, user=user)

@app.post("/users/login", response_model=schemas.Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # 1. Find the user by email (FastAPI OAuth2 uses 'username' for the email field)
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    
    # 2. Check if user exists AND password is correct
    if not user or not crud.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 3. If correct, generate the JWT token
    access_token = crud.create_access_token(data={"sub": user.email})
    
    # 4. Return the token
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.UserResponse)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# NEW ROUTE: Create an Incident Report
@app.post("/incidents/", response_model=schemas.IncidentResponse)
def create_incident_report(
    incident: schemas.IncidentCreate, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user) 
):
    # 1. Create the incident
    new_incident = crud.create_incident(db=db, incident=incident, user_id=current_user.id)
    
    # 2. THE TRIPWIRE: Silently log that they did this
    crud.create_audit_log(db=db, action_type="CREATED_INCIDENT", user_id=current_user.id)
    
    return new_incident



# ROUTE 1: Regular users view their own reports
@app.get("/users/me/incidents/", response_model=list[schemas.IncidentResponse])
def read_my_incidents(
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    return crud.get_user_incidents(db=db, user_id=current_user.id)

# ROUTE 2: Admins view all reports
@app.get("/admin/incidents/", response_model=list[schemas.IncidentResponse])
def read_all_incidents(
    db: Session = Depends(get_db), 
    current_admin: models.User = Depends(get_current_admin) # Guarded by Elite Bouncer!
):
    return crud.get_all_incidents(db=db)

# ROUTE: Admins view all audit logs
@app.get("/admin/logs/", response_model=list[schemas.AuditLogResponse])
def read_audit_logs(
    db: Session = Depends(get_db),
    current_admin: models.User = Depends(get_current_admin) # Elite Bouncer Guarding This!
):
    return crud.get_audit_logs(db=db) 

# 👑 ADMIN ROUTE: Promote a user to Admin
@app.put("/admin/promote/")
def promote_user_to_admin(
    req: schemas.UserPromote, 
    db: Session = Depends(get_db), 
    current_admin: models.User = Depends(get_current_admin)
):
    user = crud.promote_user(db=db, email=req.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"Success! {req.email} is now an Admin."}

# 🛡️ ADMIN ROUTE: Demote an Admin back to a regular User
# 🛡️ ADMIN ROUTE: Demote an Admin back to a regular User
@app.put("/admin/demote/")
def demote_admin_to_user(
    req: schemas.UserPromote, 
    db: Session = Depends(get_db), 
    current_admin: models.User = Depends(get_current_admin)
):
    # 1. CRITICAL SAFETY CHECK: Prevent an admin from demoting themselves
    if req.email.lower() == current_admin.email.lower():
        raise HTTPException(
            status_code=400, 
            detail="Security safeguard: You cannot demote your own account!"
        )

    # 2. THE IMMUNITY SHIELD: Protect the Root Creator (Replace with your actual email)
    if req.email.lower() == "kunalsinghal8678@gmail.com": 
        raise HTTPException(
            status_code=403, 
            detail="Action Forbidden: This is the immutable Root Admin account."
        )

    # 3. If it passes both checks, perform the demotion
    user = crud.demote_user(db=db, email=req.email)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    crud.create_audit_log(db=db, action_type=f"DEMOTED_USER_{user.id}", user_id=current_admin.id)
    
    return {"message": f"Success! {req.email} has been demoted to a regular user."}

# 🔒 USER ROUTE: Change own email or password
@app.put("/users/me/update")
def update_my_account(
    req: schemas.UserUpdate, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    updated_user = crud.update_user_credentials(db=db, user_id=current_user.id, updates=req)
    return {"message": "Account credentials updated successfully!"}