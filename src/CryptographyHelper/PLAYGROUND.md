# CryptographyHelper playground

Two local projects demonstrate the library: a .NET 10 minimal API and a React 19 / Vite UI with Lucide icons.

## Run

Prerequisites: .NET 10 SDK and Node.js 22.12+ (Node 24 works).

From the repository root, start the API:

```sh
dotnet run --project src/CryptographyHelper/CryptographyHelper.Playground.Api
```

In another terminal:

```sh
cd src/CryptographyHelper/CryptographyHelper.Playground.Ui
npm ci
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` to http://localhost:5180; no CORS configuration is needed. The API launch profile binds to localhost. Keep this development playground local; it has no authentication. Inputs and keys are sent to the API but are not persisted. Responses disable caching.

## Features

- MD5, SHA-1, SHA-256, SHA-384, SHA-512 and HMAC, with text, hex, Base64, or file input (up to 1 MB).
- PBKDF2 with generated salt, configurable hash, iterations, and output length.
- AES, DES, and TripleDES encryption/decryption, CBC/ECB, padding selection, random key/IV generation, and ciphertext reuse.
- RSA XML/PEM key generation (2048/3072/4096 bits), encryption/decryption, sign/verify data or precomputed hashes, encryption/signature padding, and signature reuse.
- Hex/Base64 outputs, UTF-8 display for decrypted data, copy controls, and validation errors. Base64 remains lossless for binary decrypted data.

MD5, SHA-1, DES, TripleDES, and ECB are included for legacy experiments. Symmetric encryption here mirrors the library and does not add authentication. Generate a fresh IV for each new CBC encryption. RSA can encrypt only short messages, with the limit determined by key size and padding. Certificate file/store access and server filesystem paths are intentionally not exposed by these endpoints.

## API

All operations accept JSON. Binary key, IV, salt, signature, and ciphertext values use Base64 unless a field says otherwise. `encoding` accepts `Text`, `Hex`, or `Base64`; algorithm names and operations are case-sensitive.

| Route | Request fields |
| --- | --- |
| `GET /api/health` | No body |
| `POST /api/hash` | `input`, `algorithm`, `encoding`, `hmac`, `key`, `keyEncoding` |
| `POST /api/pbkdf2` | `password`, `salt`, `iterations`, `length`, `algorithm` |
| `POST /api/random` | `length` in bytes |
| `POST /api/symmetric` | `input`, `key`, `iv`, `algorithm`, `operation`, `encoding`, `mode`, `padding` |
| `POST /api/rsa/keys` | `size`, `format` (`Xml` or `Pem`) |
| `POST /api/rsa` | `input`, `key`, `operation`, `format`, `encoding`, `padding`, `algorithm`, `signaturePadding`, `signature` |

Byte results include `hex`, `base64`, `bytes`, and optional `text`. Verification returns `verified`. Invalid cryptographic inputs return HTTP 400 Problem Details. PBKDF2 is bounded to 1,000,000 iterations and 128 output bytes; request bodies are capped at 2 MB.

## Validate

```sh
dotnet test src/CryptographyHelper/CryptographyHelper.slnx
cd src/CryptographyHelper/CryptographyHelper.Playground.Ui
npm run build
npm test
```

`npm test` requires the API running. It checks hash/HMAC and PBKDF2 against Node's independent crypto implementation, symmetric and RSA round trips, signatures, tampering, and invalid inputs. Set `API_URL` to test another local API address.

`npm run preview` serves the built UI on http://localhost:4173 and also proxies to the running API. For another deployment, host `dist` and route `/api` to the .NET application on the same origin; Vite's development proxy is not part of the static build.
