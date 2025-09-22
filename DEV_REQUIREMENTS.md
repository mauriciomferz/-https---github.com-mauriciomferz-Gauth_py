# Development Requirements

Install development and test dependencies:

```bash
pip install -e .[dev] || pip install pytest pytest-asyncio pyjwt pyseto
```

Recommended packages:

- `pytest` & `pytest-asyncio` – test framework & async support
- `pyjwt` – real JWT generation/validation (optional; falls back to mock if absent)
- `pyseto` – PASETO support (optional; mock used if absent)
- `aioredis` – planned for Redis-backed token store / rate limiter
- `prometheus-client` – planned metrics exporter integration

Run tests:

```bash
pytest -q
```

Run specific test:

```bash
pytest tests/test_rotation.py::test_rotation_grace_validation -vv
```

---
This file documents evolving dev dependencies; update as new features (Redis, metrics) are implemented.