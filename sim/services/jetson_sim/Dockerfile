FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN useradd -ms /bin/bash jetson
RUN mkdir -p /home/jetson/firmware && chown -R jetson:jetson /home/jetson

RUN pip install --no-cache-dir asyncssh

WORKDIR /app
COPY main.py /app/main.py

USER root
CMD ["python", "/app/main.py"]

