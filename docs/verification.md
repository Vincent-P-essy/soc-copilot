# Execution record

Source revision: `153e62b70c5c26195f11f9a571c4c6977f6d6147`.

A local analyst conversation using the built-in planner and documentation-range IP addresses. No external model service was called.

Command: `python -m pytest -q`.

Exit status: `0`.

```text

.
    return self._jws.encode(

tests/test_api.py::test_login_and_me
tests/test_auth.py::test_token_round_trip
  ./python-tools/lib/python3.12/site-packages/jwt/api_jwt.py:370: InsecureKeyLengthWarning: The HMAC key is 22 bytes long, which is below the minimum recommended length of 32 bytes for SHA256. See RFC 7518 Section 3.2.
    decoded = self.decode_complete(

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
46 passed, 5 warnings in 2.72s

```

The image is a browser capture of the running local application.

This check covers the local example and the commands listed above. Deployment, external integrations and performance under production load are outside this record.
