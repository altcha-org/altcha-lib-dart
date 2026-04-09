# ALTCHA Example

A minimal HTTP server demonstrating ALTCHA PoW v2 integration.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/challenge` | Issues a new signed PoW challenge |
| `POST` | `/submit` | Validates a form submission containing an ALTCHA payload |

## Run

```sh
dart run example/http_server.dart
```

The server listens on `http://localhost:3000`.
