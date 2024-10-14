from sqlalchemy import Column, Integer, String, Boolean
from ..database import db

class User(db.Model):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    is_active = Column(Boolean, default=False)
    safety_token = Column(String, nullable=True)
