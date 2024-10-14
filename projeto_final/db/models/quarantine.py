from sqlalchemy import Column, Integer, DateTime, Text, ForeignKey, String
from ..database import db

class Quarantine(db.Model):
    __tablename__ = 'quarantine'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    start_time = Column(DateTime(timezone=True), nullable=False) 
    end_time = Column(DateTime(timezone=True), nullable=False)
    reason = Column(Text, nullable=True)
    ip_address = Column(String, nullable=False)
