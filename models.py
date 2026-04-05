from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user") # Can be "user" or "admin"

    # Establishes a relationship to the Incidents table
    incidents = relationship("Incident", back_populates="reporter")

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    status = Column(String, default="Open") # Open, Investigating, Resolved
    reporter_id = Column(Integer, ForeignKey("users.id"))

    # Links back to the User who created it
    reporter = relationship("User", back_populates="incidents")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action_type = Column(String) # e.g., "VIEWED_INCIDENT", "STATUS_CHANGED"
    user_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)