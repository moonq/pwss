FROM python:3.10-slim-bullseye

ARG TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    memcached \
    && rm -rf /var/lib/apt/lists/

COPY code/requirements.txt /tmp/requirements.txt

ARG UUID=1000
RUN useradd -u $UUID -ms /bin/bash user && \
    mkdir /venv && chown $UUID /venv
USER user
RUN python3 -m venv /venv && \
  . /venv/bin/activate && \
  pip install --no-cache-dir -U pip wheel && \
  pip install --no-cache-dir -r /tmp/requirements.txt && \
  rm -rf /home/user/.cache && pip freeze > /venv/freeze.txt

EXPOSE 5000
EXPOSE 5001
COPY code /code
WORKDIR /code
CMD ["bash", "/code/start_daemon"]
