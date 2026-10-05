import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, Depends
from fastapi.responses import JSONResponse
import redis
from rq import Queue

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("gateway")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_conn = None
q = None

def init_redis():
    global redis_conn, q
    try:
        redis_conn = redis.from_url(REDIS_URL, socket_timeout=2)
        q = Queue(connection=redis_conn)
        redis_conn.ping()
        logger.info("Successfully connected to Redis & RQ.")
    except Exception as e:
        logger.error(f"Redis init failed: {e}. Running in FAIL-OPEN mode.")
        redis_conn = None
        q = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_redis()
    yield

async def inhibitor_dependency(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    
    if redis_conn:
        try:
            if redis_conn.exists(f"blacklist:{client_ip}"):
                from fastapi import HTTPException
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: IP is blacklisted")
        except redis.RedisError as e:
            logger.error(f"Redis check failed: {e}")

    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8', errors='ignore')
    except Exception:
        body_str = ""

    request_data = {
        "ip": client_ip,
        "method": request.method,
        "path": request.url.path,
        "query_string": request.url.query.decode('utf-8', errors='ignore') if isinstance(request.url.query, bytes) else request.url.query,
        "headers": dict(request.headers),
        "body": body_str
    }
    
    if q:
        try:
            q.enqueue("ai_analyzer.analyze_traffic", request_data, job_timeout='2m')
        except Exception as e:
            logger.error(f"Failed to enqueue traffic analysis: {e}")

app = FastAPI(title="Inhibitor Gateway", lifespan=lifespan, dependencies=[Depends(inhibitor_dependency)])

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def catch_all(path: str, request: Request):
    return {
        "message": "Request passed through Inhibitor successfully.",
        "path": path,
        "method": request.method
    }
