from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

Base = declarative_base()

def get_engine():
    return create_engine("sqlite:///myxnote.db", echo=False)

def get_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    is_admin = Column(Boolean, default=False)
    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")

class Note(Base):
    __tablename__ = 'notes'
    id = Column(Integer, primary_key=True)
    title = Column(String(150), nullable=False)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship("User", back_populates="notes")
