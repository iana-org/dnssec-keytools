FROM python:3.7

ARG UID=5353
ARG GID=5353

EXPOSE 8443/tcp
VOLUME /var/lib/kskm/wksr

RUN groupadd -g $GID wksr
RUN useradd -r -u $UID -g $GID wksr

RUN apt-get update
RUN apt-get install -y swig
RUN pip install gunicorn

WORKDIR /tmp
COPY dist/*.whl .
RUN pip install -f . kskm[online]
RUN rm *.whl

USER wksr
WORKDIR /home/wksr
ENTRYPOINT gunicorn --bind 0.0.0.0 kskm.wksr.app
