FROM python:3.8-slim-buster

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SUPERUSER_PASSWORD admin

COPY ./src /src

WORKDIR /src

COPY ./requirements.txt requirements.txt

EXPOSE 8000

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

