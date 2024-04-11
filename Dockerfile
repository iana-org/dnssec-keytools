# Dockerfile for building standalone wksr server

FROM python:3.12 as builder

ADD . /src
WORKDIR /src

RUN pip install poetry
RUN poetry build


FROM python:3.12

ARG UID=5353
ARG GID=5353

EXPOSE 8443/tcp
VOLUME /var/lib/kskm/wksr

RUN groupadd -g $GID wksr
RUN useradd -r -u $UID -g $GID wksr

RUN apt-get update
RUN apt-get install -y swig

WORKDIR /tmp
COPY --from=builder /src/dist/*.whl .
RUN pip install -f . kskm[online]
RUN rm *.whl

USER wksr
WORKDIR /home/wksr
ENTRYPOINT kskm-wksr
