FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/generate_data.py && PYTHONPATH=. python scripts/ingest.py
EXPOSE 8000
CMD ["uvicorn", "firewall_audit_agent.app:app", "--host", "0.0.0.0", "--port", "8000"]
