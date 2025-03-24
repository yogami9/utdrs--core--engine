from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
from config import settings
from utils.logger import get_logger
import asyncio

logger = get_logger(__name__)

class Database:
    client: AsyncIOMotorClient = None
    db_name: str = settings.DB_NAME

db = Database()
connection_established = asyncio.Event()

async def connect_to_mongo():
    try:
        logger.info(f"Connecting to MongoDB at {settings.MONGODB_URI[:20]}...")
        db.client = AsyncIOMotorClient(settings.MONGODB_URI)
        # Validate connection
        await db.client.admin.command('ping')
        logger.info("Connected to MongoDB")
        connection_established.set()
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error connecting to MongoDB: {str(e)}")
        raise

async def close_mongo_connection():
    if db.client:
        db.client.close()
        logger.info("Closed MongoDB connection")

async def get_database():
    if not connection_established.is_set():
        logger.warning("Database connection not yet established, waiting...")
        try:
            # Wait for connection with a timeout
            await asyncio.wait_for(connection_established.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.error("Timed out waiting for database connection")
            return None
    
    if db.client is None:
        logger.error("Database client is None, connection may have failed")
        return None
        
    return db.client[db.db_name]