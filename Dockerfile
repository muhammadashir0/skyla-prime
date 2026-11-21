FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic httpx python-multipart
COPY skyla/ ./skyla/
COPY apps/ ./apps/
ENV SKYLA_DB_PATH=/app/data/skyla.db
EXPOSE 8000
CMD ["uvicorn", "skyla.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
