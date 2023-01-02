FROM python:3.11.0-bullseye
RUN apt-get update && apt-get -y install nmap
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "src/scanner.py"]