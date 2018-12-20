FROM python:3.6

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY saml ./saml
COPY config.yaml ./
COPY platform.json ./
COPY start.sh ./

RUN chmod 755 ./start.sh

EXPOSE 8000

CMD ["./start.sh"]
