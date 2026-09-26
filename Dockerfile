FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /usr/local/bin/uv
# Vector's VRL runtime is the parser sandbox (D9)
COPY --from=timberio/vector:0.55.0-debian /usr/bin/vector /usr/local/bin/vector
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev && useradd --uid 1000 --create-home privasoc
ENV PATH=/app/.venv/bin:$PATH PRIVASOC_HOST=0.0.0.0 PRIVASOC_DATA_DIR=/data
USER privasoc
EXPOSE 8000
CMD ["privasoc", "serve"]
