from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean
from sqlalchemy.sql import func
from ..database import db

class Log(db.Model):
    __tablename__ = 'logs'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    event_type = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=datetime.now(timezone.utc))
    message = Column(Text, nullable=True) 
    ip_address = Column(String, nullable=False)
    success = Column(Boolean, nullable=True) 
