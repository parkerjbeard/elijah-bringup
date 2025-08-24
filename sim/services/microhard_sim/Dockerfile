FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir asyncssh fastapi uvicorn telnetlib3

WORKDIR /app

COPY main.py /app/main.py

CMD ["python", "/app/main.py"]

