FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]