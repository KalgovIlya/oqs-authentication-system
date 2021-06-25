FROM python:3.8-alpine
WORKDIR /
ENV FLASK_APP=register.py
ENV FLASK_RUN_HOST=0.0.0.0
RUN apk add --no-cache gcc musl-dev linux-headers
COPY requirements.txt requirements.txt
RUN pip install gunicorn wheel
RUN pip install -r requirements.txt
EXPOSE 5000
COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "register:app"]

