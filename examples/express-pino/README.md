# Express + Pino safe request logging

This app attaches a non-mutating `request.redacted()` snapshot after the JSON
body parser and passes it to a Pino logger protected by the same policy.

From the repository root:

```bash
npm run build
npm --prefix examples/express-pino install
npm --prefix examples/express-pino run smoke
```

To run the server yourself:

```bash
npm --prefix examples/express-pino start

curl -X POST http://127.0.0.1:3000/checkout \
  -H 'authorization: Bearer demo-token' \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","card":"4242 4242 4242 4242"}'
```

The request still contains the original data for route handling. Only the
logger receives the redacted snapshot.
