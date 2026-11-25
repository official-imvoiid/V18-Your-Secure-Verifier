# v18_verify (Python)

Check V18 age tickets on your website's **server**. Uses only the `cryptography` package.
It applies every rule in `PROTOCOL.md` section 3.7.

```python
from v18_verify import V18Verifier, ChallengeStore

verifier = V18Verifier(server_url="http://localhost:8080", origin="https://example.com")
challenges = ChallengeStore()

# 1. When the page asks for a challenge:
issued = challenges.create(visit_id)          # give issued.challenge to the widget

# 2. When the widget sends the ticket back:
result = verifier.verify_ticket(ticket, expected_challenge=challenges.checker(visit_id), min_age=18)
if result.valid:
    ...  # the visitor is 18+ (result.ticket.min_age is the age V18's key certifies)
else:
    print(result.code, result.error)
```

See `docs/web/INTEGRATION.md` for a full Flask example. Run the tests with:

```
python -m pytest tests/test_verifier.py -v
```
