import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

async_engine = create_async_engine("postgresql+asyncpg://postgres:7712@localhost:5432/postgres")
async_session = async_sessionmaker(async_engine)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
