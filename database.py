import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load the secrets from your .env file
load_dotenv()

# Get the connection string safely
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Create the engine that communicates with Postgres
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create a session factory to talk to the database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()