FROM python:3.12-slim

RUN mkdir -p /app/src
WORKDIR /app

COPY ./src/requirements.txt /app/src/requirements.txt
RUN pip install --no-cache-dir -r /app/src/requirements.txt

CMD ["python", "/app/src/bot.py"]
