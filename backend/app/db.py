from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# SQLite local file. In CI, you can swap to Postgres later.
DATABASE_URL = "sqlite:///./taskmanager.db"

engine = create_engine(
    DATABASE_URL,
    # needed for SQLite + threads
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """Récupère une session db"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
