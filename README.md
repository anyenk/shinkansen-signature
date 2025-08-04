# @anyenk/shinkansen-signature

A TypeScript library for creating and verifying signatures for Shinkansen (https://shinkansen.finance/) integration according to their security specification.

**Documentation:**
- [Message Signing Specification](https://docs.shinkansen.tech/docs/firmar-mensajes)
- [Message Verification Specification](https://docs.shinkansen.tech/docs/verificar-mensajes)

## Installation

```bash
npm install @anyenk/shinkansen-signature
```

## Usage

### Verifying Signatures

```typescript
import { verifySignature } from '@anyenk/shinkansen-signature';

// Verify a JWS signature from Shinkansen POST request
const result = await verifySignature({
  jws: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiIsIng1YyI6WyJNSUlD...',
  payload: '{"amount": 1000, "currency": "USD"}',
  trustedCertificates: ['MIICertificate1...', 'MIICertificate2...']
});

console.log(result.isValid); // true or false
console.log(result.error); // Error message if validation failed
```

### Creating Signatures

```typescript
import { createSignature } from '@anyenk/shinkansen-signature';

// Create a JWS signature for sending to Shinkansen
const result = await createSignature({
  payload: '{"amount": 1000, "currency": "USD"}',
  privateKey: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG...',
  certificate: '-----BEGIN CERTIFICATE-----\nMIICertificateData...'
});

console.log(result.signature); // Detached JWS signature
// Use this signature in the 'Shinkansen-JWS-Signature' HTTP header
```

### Real Shinkansen Example

```typescript
import { verifySignature } from '@anyenk/shinkansen-signature';

// Example with real Shinkansen data
const shinkansenJws = 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sIng1YyI6WyJNSUlFSnpDQ0F3K2dBd0lCQWdJVUFJMFVIRjIzbEdDMzJScThhaDgyV29kWU8zTXdEUVlKS29aSWh2Y05BUUVMQlFBd2dhSXhDekFKQmdOVkJBWVRBa05NTVJZd0ZBWURWUVFJREExTlpYUnliM0J2YkdsMFlXNWhNUkV3RHdZRFZRUUhEQWhUWVc1MGFXRm5iekVUTUJFR0ExVUVDZ3dLVTJocGJtdGhibk5sYmpFVE1CRUdBMVVFQ3d3S1UyaHBibXRoYm5ObGJqRVRNQkVHQTFVRUF3d0tVMmhwYm10aGJuTmxiakVwTUNjR0NTcUdTSWIzRFFFSkFSWWFaR1YyZEdWemRFQnphR2x1YTJGdWMyVnVMbVpwYm1GdVkyVXdIaGNOTWpRd09USTBNakF6TWpBMVdoY05Nall3T1RFME1qQXpNakExV2pDQm9qRUxNQWtHQTFVRUJoTUNRMHd4RmpBVUJnTlZCQWdNRFUxbGRISnZjRzlzYVhSaGJtRXhFVEFQQmdOVkJBY01DRk5oYm5ScFlXZHZNUk13RVFZRFZRUUtEQXBUYUdsdWEyRnVjMlZ1TVJNd0VRWURWUVFMREFwVGFHbHVhMkZ1YzJWdU1STXdFUVlEVlFRRERBcFRhR2x1YTJGdWMyVnVNU2t3SndZSktvWklodmNOQVFrQkZocGtaWFowWlhOMFFITm9hVzVyWVc1elpXNHVabWx1WVc1alpUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU8wMU0zZ3YreENibTVXUGJuVXExaTRNbzIxTnZGNkNPRTB4anlnRnVTYVBkTHNqNTRpYkhwKzkzTDBlSURFMUJxN05wbGtCM3hzZzNLMU5BMGJJOGpjWXpCSFRoK3JYelZjc1BrRTJOWndNTUVqUlN0TURVcVBYWkpNSkJka2tuVnIwR25qL0dmNWZQdzNzLytWYlRCYjIwQ3ZWamVxTG1DbmJxeTNKRm91VkkvUWlhOVhvOFdWMzlDMDVFRlc2ZENpazhPWWFzSHlHMFFjVkxrb281aU16cUpXRlZWc3pZaXpVcjB6bTFSaXlUWnBKcnU4OWF3VEU2UmdSbGhXYU5GTlFmRFk5ZVdWTmtzczNzSlN3RWlaVmFWMFdITnVmSlBKbVdzZE16dXBjRnErNTJPWDhHbkcrMVFyUVVoYkROYUx2UUp4dWhPSDJtVnNrdWhIc3VQMENBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGQk9ZcjkwQ3pmWUJSb09Da1V2TWNOMVNIN1NMTUI4R0ExVWRJd1FZTUJhQUZCT1lyOTBDemZZQlJvT0NrVXZNY04xU0g3U0xNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQXd3T3BVTEpYVFNLU1JXMkQwa0ZDNmdQd1ZMTzh3T3luUlpIOC82T2UxNjQwK3o4aXFZbkpzR0RZOUg1Sk4wbHBMc1Z1ZzFRSUwzZU93RVpZUEt4SFUvMUQzZVZYYmE0a1puTjRVVFZZbUtXdW1sbGw5TFdvZ0lEUW5Ja1JGREdDUWhET3g1MUUwcWdPb0hhM2RMZmd6VitnMCtHRTFoMFBCbnozWUpGU1lNbVBGNEtPNUN6dFFZRHZrb3Z0aER5clozWmFjckJ6dlB6U281SmFrWXpGV2ZMKzhROGR2N25vL3M4UlBOQklDS3pBeExFb0tibTA4OVdCYktBSTJhQmNqUVE1YjFheENjSjVJbnlRL1RTd0c2UXd2aDc3bE9lK2hxN1VUdWZKbC9acUJHZnpNcVkrdlY1TzRDcUkzTkVSREVwV0JrNUROSVVpMzh6S3htVkpBPSJdfQ..xxs8LI4Bke8nwu8xf9zjTzxwQHeo9l3f78BK1A_tlvx1r-ZXrC0-s9c_yiCD0SKv-konDUOh6u8JlCHUKOBEbgFadP6fS87212gQcDt3ltRQn7C_8qVbG23Hy7uxYSYHFbfs7w1RKWvbgzo9j8ICSazbm-2SKeLvPSnPqhiFcQQ9Md2z11BEALcWv778uvtHU6pLpPxBFsgMbh1CUP3bY7GtSitpba8hPyKP3doCCTUYEa4lADDxjmzRKY-XIzbiEVO82GMHExNucmTB1cTM-hQX3QJoWPDzAHqVIMeAObyQZrJal8_dje-9hUEwZqyAz0nWGewgKeXn3ipx43-MLg';

const shinkansenPayload = '{"document":{"header":{"creation_date":"2025-08-04T21:00:57Z","message_id":"6ebaf63f-eeb5-464e-bf3b-a4ec21627c76","receiver":{"fin_id":"ANYENK_CL","fin_id_schema":"SHINKANSEN"},"sender":{"fin_id":"SHINKANSEN","fin_id_schema":"SHINKANSEN"},"shinkansen_message_id":"5190f257-2346-4633-8afa-e15ea7a1800c"},"notifications":[{"amount":"100000.00000","creditor":{"account":"30002590","account_type":"current_account","financial_institution":{"fin_id":"SIMULATED_BANK","fin_id_schema":"SHINKANSEN"},"identification":{"id":"60000159-0","id_schema":"CLID"},"name":"Anyenk"},"currency":"CLP","debtor":{"account":"30002590","account_type":"current_account","financial_institution":{"fin_id":"SIMULATED_BANK","fin_id_schema":"SHINKANSEN"},"identification":{"id":"60000159-0","id_schema":"CLID"},"name":"Anyenk"},"description":"Depositar dinero test0","notification_date":"2025-08-04T21:00:57Z","notification_id":"0c3d19d0-b61d-4e65-b78b-09a9cfbbd27b","notification_type":"payin","original_notification_id":"f5da362c-1134-4e63-95ce-890c780b929e","payment_operator_metadata":null,"referenced_shinkansen_notification_ids":null,"shinkansen_notification_id":"72edbeb6-36b5-4e7b-9914-8601cc94f53d","transaction_accounting_date":"2025-08-04T21:00:57Z","transaction_accounting_id":null,"transaction_date":"2025-08-04T21:00:57Z"}]}}';

const shinkansenCertificate = `-----BEGIN CERTIFICATE-----
MIIEJzCCAw+gAwIBAgIUAI0UHF23lGC32Rq8ah82WodYO3MwDQYJKoZIhvcNAQEL
BQAwgaIxCzAJBgNVBAYTAkNMMRYwFAYDVQQIDA1NZXRyb3BvbGl0YW5hMREwDwYD
VQQHDAhTYW50aWFnbzETMBEGA1UECgwKU2hpbmthbnNlbjETMBEGA1UECwwKU2hp
bmthbnNlbjETMBEGA1UEAwwKU2hpbmthbnNlbjEpMCcGCSqGSIb3DQEJARYaZGV2
dGVzdEBzaGlua2Fuc2VuLmZpbmFuY2UwHhcNMjQwOTI0MjAzMjA1WhcNMjYwOTE0
MjAzMjA1WjCBojELMAkGA1UEBhMCQ0wxFjAUBgNVBAgMDU1ldHJvcG9saXRhbmEx
ETAPBgNVBAcMCFNhbnRpYWdvMRMwEQYDVQQKDApTaGlua2Fuc2VuMRMwEQYDVQQL
DApTaGlua2Fuc2VuMRMwEQYDVQQDDApTaGlua2Fuc2VuMSkwJwYJKoZIhvcNAQkB
FhpkZXZ0ZXN0QHNoaW5rYW5zZW4uZmluYW5jZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAO01M3gv+xCbm5WPbnUq1i4Mo21NvF6COE0xjygFuSaPdLsj
54ibHp+93L0eIDE1Bq7NplkB3xsg3K1NA0bI8jcYzBHTh+rXzVcsPkE2NZwMMEjR
StMDUqPXZJMJBdkknVr0Gnj/Gf5fPw3s/+VbTBb20CvVjeqLmCnbqy3JFouVI/Qi
a9Xo8WV39C05EFW6dCik8OYasHyG0QcVLkoo5iMzqJWFVVszYizUr0zm1RiyTZpJ
ru89awTE6RgRlhWaNFNQfDY9eWVNkss3sJSwEiZVaV0WHNufJPJmWsdMzupcFq+5
2OX8GnG+1QrQUhbDNaLvQJxuhOH2mVskuhHsuP0CAwEAAaNTMFEwHQYDVR0OBBYE
FBOYr90CzfYBRoOCkUvMcN1SH7SLMB8GA1UdIwQYMBaAFBOYr90CzfYBRoOCkUvM
cN1SH7SLMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAAwwOpUL
JXTSKSRW2D0kFC6gPwVLO8wOynRZH8/6Oe1640+z8iqYnJsGDY9H5JN0lpLsVug1
QIL3eOwEZYPKxHU/1D3eVXba4kZnN4UTVYmKWumlll9LWogIDQnIkRFDGCQhDOx5
1E0qgOoHa3dLfgzV+g0+GE1h0PBnz3YJFSYMmPF4KO5CztQYDvkovthDyrZ3Zacr
BzvPzSo5JakYzFWfL+8Q8dv7no/s8RPNBICKzAxLEoKbm089WBbKAI2aBcjQQ5b1
axCcJ5InyQ/TSwG6Qwvh77lOe+hq7UTufJl/ZqBGfzMqY+vV5O4CqI3NERDEpWBk
5DNIUi38zKxmVJA=
-----END CERTIFICATE-----`;

const result = await verifySignature({
  jws: shinkansenJws,
  payload: shinkansenPayload,
  trustedCertificates: [shinkansenCertificate]
});

console.log(result.isValid); // true
console.log('Verified real Shinkansen signature successfully!');
```

## Features

This library implements both signature creation and verification according to Shinkansen specifications:

**Signature Creation:**
- JWS detached signatures with PS256 algorithm
- Certificate embedding in `x5c` header (DER format)
- Support for `b64: false` for unencoded payloads
- Proper `Shinkansen-JWS-Signature` header format

**Signature Verification:**
- JWS (JSON Web Signature) with PS256 algorithm validation
- X.509 certificate validation against trusted whitelists
- Certificate expiration checks
- Exact payload verification without JSON parsing/re-stringification

## Development

### Scripts

- `npm run build` - Build the library
- `npm run dev` - Build in watch mode
- `npm test` - Run tests
- `npm run test:watch` - Run tests in watch mode
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Run ESLint with auto-fix
- `npm run typecheck` - Type check without emitting files

### Testing

Tests are written using Jest and located in `src/__tests__/`.

```bash
npm test
```

## License

MIT