ARG BASE_IMAGE=python:3.8.13-slim-buster
FROM $BASE_IMAGE

ENV POETRY_HOME=/etc/poetry \
    POETRY_VERSION=1.1.12 \
    POETRY_VIRTUALENVS_CREATE=0 \
    POETRY_VIRTUALENVS_IN_PROJECT=0 \
    POETRY_NO_INTERACTION=1

RUN BUILD_DEPS='curl' \
    && apt-get update -y \
    && apt-get install --no-install-recommends -y \
        $BUILD_DEPS \
    && rm -r /var/lib/apt/lists/* \
    # Install poetry
    && curl -sSL https://install.python-poetry.org | python \
    && apt-get purge -y --auto-remove $BUILD_DEPS

# install project requirements
COPY ./pyproject.toml ./poetry.lock ./
RUN $POETRY_HOME/bin/poetry install --no-root

# add kedro user
ARG KEDRO_UID=999
ARG KEDRO_GID=0
RUN groupadd -f -g ${KEDRO_GID} kedro_group && \
useradd -d /home/kedro -s /bin/bash -g ${KEDRO_GID} -u ${KEDRO_UID} kedro

# copy the whole project except what is in .dockerignore
WORKDIR /home/kedro
COPY . .
RUN chown -R kedro:${KEDRO_GID} /home/kedro
USER kedro
RUN chmod -R a+w /home/kedro

ENV PORT 8888

CMD ["kedro", "run"]
