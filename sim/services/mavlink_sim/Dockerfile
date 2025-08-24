FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir pymavlink

WORKDIR /app
COPY mavlink_sim.py /app/mavlink_sim.py

CMD ["python", "/app/mavlink_sim.py"]

