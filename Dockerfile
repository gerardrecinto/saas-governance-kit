FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --system --uid 10001 scim && mkdir /data && chown scim /data
USER scim

EXPOSE 8080
# Set SCIM_BEARER_TOKEN at run time. Mount /data to keep the JSON store.
ENTRYPOINT ["scim-server"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--store", "/data/scim-data.json"]
