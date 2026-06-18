FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 httpx==0.27.0 uvicorn[standard]==0.30.1 pymysql==1.1.0 psycopg2-binary==2.9.9

COPY prompt_guard.py /app/prompt_guard.py
COPY prompt_guard_rules.json /app/rules.json

EXPOSE 8080

CMD ["uvicorn", "prompt_guard:app", "--host", "0.0.0.0", "--port", "8080"]
