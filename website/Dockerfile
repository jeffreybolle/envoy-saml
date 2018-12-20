FROM python:3.6

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY website.py ./

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0", "--workers", "4", "website:app"]
