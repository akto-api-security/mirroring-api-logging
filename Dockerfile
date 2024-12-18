FROM coastaldemigod/echo-server-python:v1
COPY app.py /app
CMD ["python3", "-m", "flask", "run", "--host", "0.0.0.0", "--port", "9080"]
