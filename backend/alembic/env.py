from alembic import context
from sqlalchemy import create_engine, pool
from app.config import Settings, load_settings
from app.models import Base

config = context.config
url = config.attributes.get("database_url") or load_settings().database_url.get_secret_value()
if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True, dialect_opts={"paramstyle":"named"})
    with context.begin_transaction(): context.run_migrations()
else:
    engine = create_engine(url, poolclass=pool.NullPool, hide_parameters=True, connect_args={"prepare_threshold":None} if url.startswith("postgresql") else {})
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction(): context.run_migrations()
    engine.dispose()
