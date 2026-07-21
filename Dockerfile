FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    CLOUD_PC_CONFIG_FILE=/app/data/cloud_pc.json

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data && chmod 0775 /app/data

EXPOSE 8080

ENTRYPOINT ["python", "main.py"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
