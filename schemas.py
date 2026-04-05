import datetime
from pydantic import BaseModel, EmailStr

# What we expect the user to send us when they sign up
class UserCreate(BaseModel):
    email: EmailStr
    password: str

# What we send back to the user (Notice we DO NOT send the password back!)
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str

    class Config:
        from_attributes = True


# Add this below your existing UserResponse class
class Token(BaseModel):
    access_token: str
    token_type: str

# What the user sends us to create a report
class IncidentCreate(BaseModel):
    title: str
    description: str

# What we send back to confirm it was created
class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    status: str
    reporter_id: int

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: int
    action_type: str
    user_id: int
    timestamp: datetime.datetime

    class Config:
        from_attributes = True