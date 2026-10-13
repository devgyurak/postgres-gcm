# SPDX-License-Identifier: PostgreSQL
# The runner of the load harness: Python and psycopg, nothing of the extension. It reaches the
# server over SQL alone, so it is built from tests/load/ and from nothing else.
# The base is pinned here, not in docker/versions.json, which lists the server images; refresh
# the digest by hand together with the pin in requirements.txt.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

COPY requirements.txt /load/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r /load/requirements.txt
COPY run.py baseline.json /load/

USER nobody
WORKDIR /load
ENTRYPOINT ["python", "run.py"]
