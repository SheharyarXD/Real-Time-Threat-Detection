from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

def database(settings):
    url = settings.database_url.get_secret_value()
    engine = create_engine(url, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {"prepare_threshold":None}, hide_parameters=True)
    if url.startswith("sqlite"):
        @event.listens_for(engine,"connect")
        def foreign_keys(connection,record): connection.execute("PRAGMA foreign_keys=ON")
    return engine, sessionmaker(bind=engine, expire_on_commit=False)
