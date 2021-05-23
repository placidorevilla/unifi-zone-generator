FROM python:3.9-alpine AS builder
COPY requirements.txt .

RUN pip install --user -r requirements.txt

FROM python:3.9-alpine
WORKDIR /config

ENV PATH=/root/.local:$PATH
ENV UNIFILOCAL_TEMPLATE=/data/localzone.template

COPY --from=builder /root/.local /root/.local
COPY ./localzone.template /data/
COPY ./src /app

CMD [ "python", "/app/unifilocal.py" ]
