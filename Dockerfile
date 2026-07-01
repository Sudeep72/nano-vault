FROM python:3.12-slim

WORKDIR /app

# Only runtime libs needed — no gcc, no -dev packages
# libpq5 is the runtime PostgreSQL client (asyncpg uses it)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Python deps — all wheels, no compilation needed
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
