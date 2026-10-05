FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run the RQ worker
CMD ["sh", "-c", "rq worker -u ${REDIS_URL:-redis://localhost:6379}"]
