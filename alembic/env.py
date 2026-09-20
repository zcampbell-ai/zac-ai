from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from zacai.config import get_settings
from zacai.state import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The single source of truth for the DB URL is Settings.database_url
# (D026), not a value duplicated into alembic.ini - so dev/prod never
# drift out of sync with the application's own configuration.
#
# D027: a caller (tests/conftest.py) may set "sqlalchemy.url" explicitly
# via config.set_main_option() *before* invoking alembic's Python API, to
# point migrations at the disposable zacai_test database instead of
# zacai_dev. This must be checked first and left alone if already set -
# unconditionally overwriting it here would silently redirect a
# test-database reset back onto zacai_dev, defeating D027 entirely.
_placeholder_url = "driver://user:pass@localhost/dbname"
if config.get_main_option("sqlalchemy.url") in (None, _placeholder_url):
    config.set_main_option("sqlalchemy.url", get_settings().database_url)

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
