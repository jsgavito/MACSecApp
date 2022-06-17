FROM alpine:3.10

RUN apk add --no-cache --virtual .pynacl_deps build-base python3-dev libffi-dev libxml2-utils libxslt gcc musl-dev libxslt-dev\
    && pip3 install --upgrade pip \
    && pip3 install --upgrade setuptools

WORKDIR /app

COPY ./app /app

RUN pip3 --no-cache-dir install -r requirements.txt

EXPOSE 5000

CMD python3 /app/app.py