FROM python:3.12-slim

WORKDIR /app

COPY ./src /app/src/
RUN pip install --no-cache-dir -r /app/src/requirements.txt

CMD ["python", "/app/src/bot.py"]
