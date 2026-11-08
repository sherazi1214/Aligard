# Production image (web aur worker dono isi se; worker ka command override hota hai). Non-root user.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
COPY engine ./engine
COPY web ./web
COPY scripts ./scripts
COPY alembic.ini ./alembic.ini
RUN useradd --create-home appuser
USER appuser
EXPOSE 8000
# Liveness sirf process dekhta hai (DB/Redis down par restart-loop nahi); readiness alag monitor hota hai
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"
# 1 worker: background kaam alag worker process karta hai. --no-access-log: uvicorn query string (tokens) log karta hai,
# hamara masked access log use hota hai.
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
