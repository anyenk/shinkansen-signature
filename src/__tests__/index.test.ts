import { verifySignature, createSignature, VerifySignatureOptions, CreateSignatureOptions } from '../index';

describe('verifySignature', () => {
  const mockCertificate = 'MIICertificateData...';
  const mockPayload = '{"amount": 1000, "currency": "USD"}';

  it('should reject invalid algorithm', async () => {
    const options: VerifySignatureOptions = {
      jws: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload.signature',
      payload: mockPayload,
      trustedCertificates: [mockCertificate]
    };

    const result = await verifySignature(options);
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Invalid algorithm');
  });

  it('should reject missing x5c certificate', async () => {
    const options: VerifySignatureOptions = {
      jws: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9.payload.signature',
      payload: mockPayload,
      trustedCertificates: [mockCertificate]
    };

    const result = await verifySignature(options);
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Missing x5c certificate');
  });

  it('should reject invalid certificate format in JWS header', async () => {
    // JWS with x5c containing invalid certificate data
    const jwsWithInvalidCert = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiIsIng1YyI6WyJpbnZhbGlkLWNlcnRpZmljYXRlLWRhdGEiXX0.payload.signature';
    const options: VerifySignatureOptions = {
      jws: jwsWithInvalidCert,
      payload: mockPayload,
      trustedCertificates: [mockCertificate]
    };

    const result = await verifySignature(options);
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Invalid certificate format in JWS header');
  });

  it('should reject untrusted certificate', async () => {
    // Use the real Shinkansen JWS but with a different trusted certificate
    const realJws = 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sIng1YyI6WyJNSUlFSnpDQ0F3K2dBd0lCQWdJVUFJMFVIRjIzbEdDMzJScThhaDgyV29kWU8zTXdEUVlKS29aSWh2Y05BUUVMQlFBd2dhSXhDekFKQmdOVkJBWVRBa05NTVJZd0ZBWURWUVFJREExTlpYUnliM0J2YkdsMFlXNWhNUkV3RHdZRFZRUUhEQWhUWVc1MGFXRm5iekVUTUJFR0ExVUVDZ3dLVTJocGJtdGhibk5sYmpFVE1CRUdBMVVFQ3d3S1UyaHBibXRoYm5ObGJqRVRNQkVHQTFVRUF3d0tVMmhwYm10aGJuTmxiakVwTUNjR0NTcUdTSWIzRFFFSkFSWWFaR1YyZEdWemRFQnphR2x1YTJGdWMyVnVMbVpwYm1GdVkyVXdIaGNOTWpRd09USTBNakF6TWpBMVdoY05Nall3T1RFME1qQXpNakExV2pDQm9qRUxNQWtHQTFVRUJoTUNRMHd4RmpBVUJnTlZCQWdNRFUxbGRISnZjRzlzYVhSaGJtRXhFVEFQQmdOVkJBY01DRk5oYm5ScFlXZHZNUk13RVFZRFZRUUtEQXBUYUdsdWEyRnVjMlZ1TVJNd0VRWURWUVFMREFwVGFHbHVhMkZ1YzJWdU1STXdFUVlEVlFRRERBcFRhR2x1YTJGdWMyVnVNU2t3SndZSktvWklodmNOQVFrQkZocGtaWFowWlhOMFFITm9hVzVyWVc1elpXNHVabWx1WVc1alpUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU8wMU0zZ3YreENibTVXUGJuVXExaTRNbzIxTnZGNkNPRTB4anlnRnVTYVBkTHNqNTRpYkhwKzkzTDBlSURFMUJxN05wbGtCM3hzZzNLMU5BMGJJOGpjWXpCSFRoK3JYelZjc1BrRTJOWndNTUVqUlN0TURVcVBYWkpNSkJka2tuVnIwR25qL0dmNWZQdzNzLytWYlRCYjIwQ3ZWamVxTG1DbmJxeTNKRm91VkkvUWlhOVhvOFdWMzlDMDVFRlc2ZENpazhPWWFzSHlHMFFjVkxrb281aU16cUpXRlZWc3pZaXpVcjB6bTFSaXlUWnBKcnU4OWF3VEU2UmdSbGhXYU5GTlFmRFk5ZVdWTmtzczNzSlN3RWlaVmFWMFdITnVmSlBKbVdzZE16dXBjRnErNTJPWDhHbkcrMVFyUVVoYkROYUx2UUp4dWhPSDJtVnNrdWhIc3VQMENBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGQk9ZcjkwQ3pmWUJSb09Da1V2TWNOMVNIN1NMTUI4R0ExVWRJd1FZTUJhQUZCT1lyOTBDemZZQlJvT0NrVXZNY04xU0g3U0xNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQXd3T3BVTEpYVFNLU1JXMkQwa0ZDNmdQd1ZMTzh3T3luUlpIOC82T2UxNjQwK3o4aXFZbkpzR0RZOUg1Sk4wbHBMc1Z1ZzFRSUwzZU93RVpZUEt4SFUvMUQzZVZYYmE0a1puTjRVVFZZbUtXdW1sbGw5TFdvZ0lEUW5Ja1JGREdDUWhET3g1MUUwcWdPb0hhM2RMZmd6VitnMCtHRTFoMFBCbnozWUpGU1lNbVBGNEtPNUN6dFFZRHZrb3Z0aER5clozWmFjckJ6dlB6U281SmFrWXpGV2ZMKzhROGR2N25vL3M4UlBOQklDS3pBeExFb0tibTA4OVdCYktBSTJhQmNqUVE1YjFheENjSjVJbnlRL1RTd0c2UXd2aDc3bE9lK2hxN1VUdWZKbC9acUJHZnpNcVkrdlY1TzRDcUkzTkVSREVwV0JrNUROSVVpMzh6S3htVkpBPSJdfQ..xxs8LI4Bke8nwu8xf9zjTzxwQHeo9l3f78BK1A_tlvx1r-ZXrC0-s9c_yiCD0SKv-konDUOh6u8JlCHUKOBEbgFadP6fS87212gQcDt3ltRQn7C_8qVbG23Hy7uxYSYHFbfs7w1RKWvbgzo9j8ICSazbm-2SKeLvPSnPqhiFcQQ9Md2z11BEALcWv778uvtHU6pLpPxBFsgMbh1CUP3bY7GtSitpba8hPyKP3doCCTUYEa4lADDxjmzRKY-XIzbiEVO82GMHExNucmTB1cTM-hQX3QJoWPDzAHqVIMeAObyQZrJal8_dje-9hUEwZqyAz0nWGewgKeXn3ipx43-MLg';
    const realPayload = '{"document":{"header":{"creation_date":"2025-08-04T21:00:57Z","message_id":"6ebaf63f-eeb5-464e-bf3b-a4ec21627c76","receiver":{"fin_id":"ANYENK_CL","fin_id_schema":"SHINKANSEN"},"sender":{"fin_id":"SHINKANSEN","fin_id_schema":"SHINKANSEN"},"shinkansen_message_id":"5190f257-2346-4633-8afa-e15ea7a1800c"},"notifications":[{"amount":"100000.00000","creditor":{"account":"30002590","account_type":"current_account","financial_institution":{"fin_id":"SIMULATED_BANK","fin_id_schema":"SHINKANSEN"},"identification":{"id":"60000159-0","id_schema":"CLID"},"name":"Anyenk"},"currency":"CLP","debtor":{"account":"30002590","account_type":"current_account","financial_institution":{"fin_id":"SIMULATED_BANK","fin_id_schema":"SHINKANSEN"},"identification":{"id":"60000159-0","id_schema":"CLID"},"name":"Anyenk"},"description":"Depositar dinero test0","notification_date":"2025-08-04T21:00:57Z","notification_id":"0c3d19d0-b61d-4e65-b78b-09a9cfbbd27b","notification_type":"payin","original_notification_id":"f5da362c-1134-4e63-95ce-890c780b929e","payment_operator_metadata":null,"referenced_shinkansen_notification_ids":null,"shinkansen_notification_id":"72edbeb6-36b5-4e7b-9914-8601cc94f53d","transaction_accounting_date":"2025-08-04T21:00:57Z","transaction_accounting_id":null,"transaction_date":"2025-08-04T21:00:57Z"}]}}';
    
    const options: VerifySignatureOptions = {
      jws: realJws,
      payload: realPayload,
      trustedCertificates: ['MIIDifferentCertificate...'] // Different certificate
    };

    const result = await verifySignature(options);
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Certificate not in trusted whitelist');
  });
});

describe('createSignature', () => {
  const mockPayload = '{"amount": 1000, "currency": "USD"}';

  it('should return error for invalid private key', async () => {
    const options: CreateSignatureOptions = {
      payload: mockPayload,
      privateKey: 'invalid-key',
      certificate: '-----BEGIN CERTIFICATE-----\nMockCertificateData...\n-----END CERTIFICATE-----'
    };

    const result = await createSignature(options);
    expect(result.signature).toBe('');
    expect(result.error).toContain('Invalid private key format');
  });

  it('should return error for invalid certificate format', async () => {
    // Using the actual valid private key from integration tests
    const validPrivateKey = `-----BEGIN PRIVATE KEY-----
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
UzOio9Sd/Al9TYVYsNI0+oPIpnsyqg==
-----END PRIVATE KEY-----`;
    
    const options: CreateSignatureOptions = {
      payload: mockPayload,
      privateKey: validPrivateKey,
      certificate: '-----BEGIN CERTIFICATE-----\nInvalidCertificateData\n-----END CERTIFICATE-----'
    };

    const result = await createSignature(options);
    expect(result.signature).toBe('');
    expect(result.error).toContain('Invalid certificate format');
  });

  it('should return error for invalid inputs', async () => {
    const options: CreateSignatureOptions = {
      payload: mockPayload,
      privateKey: 'invalid-private-key',
      certificate: 'invalid-certificate'
    };

    const result = await createSignature(options);
    expect(result.signature).toBe('');
    expect(result.error).toBeDefined();
    // Either private key or certificate validation can fail, both are acceptable
    expect(result.error).toMatch(/Invalid (private key|certificate) format/);
  });
});

describe('README Examples', () => {
  it('should handle basic verification example (expected to fail with invalid data)', async () => {
    const result = await verifySignature({
      jws: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiIsIng1YyI6WyJNSUlD...',
      payload: '{"amount": 1000, "currency": "USD"}',
      trustedCertificates: ['MIICertificate1...', 'MIICertificate2...']
    });

    expect(result.isValid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should handle basic creation example (expected to fail with invalid keys)', async () => {
    const result = await createSignature({
      payload: '{"amount": 1000, "currency": "USD"}',
      privateKey: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG...',
      certificate: '-----BEGIN CERTIFICATE-----\nMIICertificateData...'
    });

    expect(result.signature).toBe('');
    expect(result.error).toBeDefined();
  });
});

describe('Integration Tests', () => {
  const testPrivateKey = `-----BEGIN PRIVATE KEY-----
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
UzOio9Sd/Al9TYVYsNI0+oPIpnsyqg==
-----END PRIVATE KEY-----`;

  const testCertificate = `-----BEGIN CERTIFICATE-----
MIIFtzCCA5+gAwIBAgIUQLgueBEp/UYNOI/8eHz60CupC4UwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJh
bmNpc2NvMQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MRkwFwYDVQQDDBB0
ZXN0LmV4YW1wbGUuY29tMB4XDTI1MDgwNDIwMzQzNFoXDTI2MDgwNDIwMzQzNFow
azELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNp
c2NvMQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MRkwFwYDVQQDDBB0ZXN0
LmV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjB9c
CrHznSqy8v78S/cOr90bAUDnYzBzda1RmqZ0QBiGQnCHhi/TWW/PacrXO0aldTzV
QOQPb+9rL6SCnefYNw3vhkWV91YTMtY6UKplDwZU4PWjWG05iLLDyyCxLgMjQ11a
lTlD6RnbNRE8vQqCVbYVM9hE2umPllzSH/debrqLYHAMJ8beqfieAiQt1t5g0PJe
CaphvZXQm8ktzoNcZe+RxJg+KNa+geNEwP6+z/R1/aWtRET9ni+4xbt93m/HgXP8
IdbVySNs2CHZzoe3awHJ5hNr5Fh+Dbc4xFXHuDmKvU6R0/vCh9NvukVXuaspa2DB
c9yyc2KPxl3mQ864XQycg/Ks+k8IXEub8XdLaD6//MBORqsiYF/HR93ORr1hl6Lx
zXGVSqyp+oNIE3YUnY6k+4mQNanCzIk1RRrvA9+WcJi8tWVGM4B7tjipqYd0wUdJ
nACBmCqiKnNnDQWHFOD0o+rxLFYddp1oYZyJE1Nwx8KRBPwcQ+PMPkKwkeq6DdlE
Vc5J6yp/oipZb6Ylvp/RfB7yDnhFVEhWCDIeRmr52BSvyTWbrjgrgAbsyU3c5uSx
XRiNSvOzW8VtRRgqoPrh9OWdpi0CxWnC3iPVv9thsqZLIsD9uhI+MzzrrtG7kH/m
064PnpHWThWN5AUPUmWquliowlIzgtF4ansQH8UCAwEAAaNTMFEwHQYDVR0OBBYE
FOGy8CQXEqriXBCFK5RUzya2thoXMB8GA1UdIwQYMBaAFOGy8CQXEqriXBCFK5RU
zya2thoXMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAB3IOwCO
sal8IzK5EdKrUW1mUVrtHnCo3WeuQsDFOBxVoRnAPWZRt6vJHq89fFjdEG7zAI14
KQGSad0CpIfuBVR/hUH4VnkSiIdIWyrd4sfc1xTNqOoXCKoS/O7/FWlSz9dxRV6G
+AbXnIxYhRFjCCcCOan+GwiWzDHPnJeb7Y55objPpQ2wYt4ScpMXCRhWS+tsTslf
iq8o17nhB691gCyibW4JQCt60mhH/gzns/SJaTORGKeSA+Z3zUbZAQRRD7FjnWzl
eszQdBaxU/1Ay1CrGWiZA58R1iqTjq+xMbbwWrhB1D89cl6a2uu1YevOciF1cfCa
G4RIh0oWBT946MmiaHC33XNp0m8+qApspjwqDxocfrCmjb9+mn2WMbSz30SRRHJ8
tJ3ExIOiJDK4iuA/0T1RDRb/BKMMigFJaS5cYT+xpQhUU8y09hAQVC6gJENSHZPE
vCOh3L/JE1QrcOCNMQ/msmmULQ2sc273hb4RN/e5EdN0GbtIvjDiVc53l4hzj9jb
C4xe2b0JYWzyKhAu1tc2EjrbbngH/cuLklQoaoH4QjoC+MY9f/eRncLBOJD+obB5
32mrwMZh0hfJsR8KFEBUBQOI/l3D0mJB78FFHgYwrdF/ZHruhngNN/Y3U0i8xQrd
wdqMLcqm1Uda05E9f2gDN5tLDDYC8gedT3OX
-----END CERTIFICATE-----`;

  const testPayload = '{"transaction_id": "12345", "amount": 1000, "currency": "USD"}';

  it('should create and verify signature successfully', async () => {
    // Step 1: Create signature
    const signatureResult = await createSignature({
      payload: testPayload,
      privateKey: testPrivateKey,
      certificate: testCertificate
    });

    expect(signatureResult.signature).toBeTruthy();
    expect(signatureResult.error).toBeUndefined();
    expect(signatureResult.signature).toMatch(/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/); // Format: header..signature

    // Step 2: Verify the signature we just created
    const verifyResult = await verifySignature({
      jws: signatureResult.signature,
      payload: testPayload,
      trustedCertificates: [testCertificate]
    });

    if (!verifyResult.isValid) {
      console.log('Verification error:', verifyResult.error);
    }
    expect(verifyResult.isValid).toBe(true);
    expect(verifyResult.error).toBeUndefined();
  });

  it('should fail verification with wrong payload', async () => {
    // Create signature with one payload
    const signatureResult = await createSignature({
      payload: testPayload,
      privateKey: testPrivateKey,
      certificate: testCertificate
    });

    expect(signatureResult.signature).toBeTruthy();

    // Try to verify with different payload
    const wrongPayload = '{"transaction_id": "54321", "amount": 2000, "currency": "EUR"}';
    const verifyResult = await verifySignature({
      jws: signatureResult.signature,
      payload: wrongPayload,
      trustedCertificates: [testCertificate]
    });

    expect(verifyResult.isValid).toBe(false);
    expect(verifyResult.error).toBeDefined();
  });

  it('should fail verification with untrusted certificate', async () => {
    // Create signature
    const signatureResult = await createSignature({
      payload: testPayload,
      privateKey: testPrivateKey,
      certificate: testCertificate
    });

    expect(signatureResult.signature).toBeTruthy();

    // Try to verify with different trusted certificate
    const differentCertificate = 'MIIDifferentCertificate...';
    const verifyResult = await verifySignature({
      jws: signatureResult.signature,
      payload: testPayload,
      trustedCertificates: [differentCertificate]
    });

    expect(verifyResult.isValid).toBe(false);
    expect(verifyResult.error).toContain('Certificate not in trusted whitelist');
  });

  it('should verify real Shinkansen signature', async () => {
    const realJws = 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sIng1YyI6WyJNSUlFSnpDQ0F3K2dBd0lCQWdJVUFJMFVIRjIzbEdDMzJScThhaDgyV29kWU8zTXdEUVlKS29aSWh2Y05BUUVMQlFBd2dhSXhDekFKQmdOVkJBWVRBa05NTVJZd0ZBWURWUVFJREExTlpYUnliM0J2YkdsMFlXNWhNUkV3RHdZRFZRUUhEQWhUWVc1MGFXRm5iekVUTUJFR0ExVUVDZ3dLVTJocGJtdGhibk5sYmpFVE1CRUdBMVVFQ3d3S1UyaHBibXRoYm5ObGJqRVRNQkVHQTFVRUF3d0tVMmhwYm10aGJuTmxiakVwTUNjR0NTcUdTSWIzRFFFSkFSWWFaR1YyZEdWemRFQnphR2x1YTJGdWMyVnVMbVpwYm1GdVkyVXdIaGNOTWpRd09USTBNakF6TWpBMVdoY05Nall3T1RFME1qQXpNakExV2pDQm9qRUxNQWtHQTFVRUJoTUNRMHd4RmpBVUJnTlZCQWdNRFUxbGRISnZjRzlzYVhSaGJtRXhFVEFQQmdOVkJBY01DRk5oYm5ScFlXZHZNUk13RVFZRFZRUUtEQXBUYUdsdWEyRnVjMlZ1TVJNd0VRWURWUVFMREFwVGFHbHVhMkZ1YzJWdU1STXdFUVlEVlFRRERBcFRhR2x1YTJGdWMyVnVNU2t3SndZSktvWklodmNOQVFrQkZocGtaWFowWlhOMFFITm9hVzVyWVc1elpXNHVabWx1WVc1alpUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU8wMU0zZ3YreENibTVXUGJuVXExaTRNbzIxTnZGNkNPRTB4anlnRnVTYVBkTHNqNTRpYkhwKzkzTDBlSURFMUJxN05wbGtCM3hzZzNLMU5BMGJJOGpjWXpCSFRoK3JYelZjc1BrRTJOWndNTUVqUlN0TURVcVBYWkpNSkJka2tuVnIwR25qL0dmNWZQdzNzLytWYlRCYjIwQ3ZWamVxTG1DbmJxeTNKRm91VkkvUWlhOVhvOFdWMzlDMDVFRlc2ZENpazhPWWFzSHlHMFFjVkxrb281aU16cUpXRlZWc3pZaXpVcjB6bTFSaXlUWnBKcnU4OWF3VEU2UmdSbGhXYU5GTlFmRFk5ZVdWTmtzczNzSlN3RWlaVmFWMFdITnVmSlBKbVdzZE16dXBjRnErNTJPWDhHbkcrMVFyUVVoYkROYUx2UUp4dWhPSDJtVnNrdWhIc3VQMENBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGQk9ZcjkwQ3pmWUJSb09Da1V2TWNOMVNIN1NMTUI4R0ExVWRJd1FZTUJhQUZCT1lyOTBDemZZQlJvT0NrVXZNY04xU0g3U0xNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQXd3T3BVTEpYVFNLU1JXMkQwa0ZDNmdQd1ZMTzh3T3luUlpIOC82T2UxNjQwK3o4aXFZbkpzR0RZOUg1Sk4wbHBMc1Z1ZzFRSUwzZU93RVpZUEt4SFUvMUQzZVZYYmE0a1puTjRVVFZZbUtXdW1sbGw5TFdvZ0lEUW5Ja1JGREdDUWhET3g1MUUwcWdPb0hhM2RMZmd6VitnMCtHRTFoMFBCbnozWUpGU1lNbVBGNEtPNUN6dFFZRHZrb3Z0aER5clozWmFjckJ6dlB6U281SmFrWXpGV2ZMKzhROGR2N25vL3M4UlBOQklDS3pBeExFb0tibTA4OVdCYktBSTJhQmNqUVE1YjFheENjSjVJbnlRL1RTd0c2UXd2aDc3bE9lK2hxN1VUdWZKbC9acUJHZnpNcVkrdlY1TzRDcUkzTkVSREVwV0JrNUROSVVpMzh6S3htVkpBPSJdfQ..xxs8LI4Bke8nwu8xf9zjTzxwQHeo9l3f78BK1A_tlvx1r-ZXrC0-s9c_yiCD0SKv-konDUOh6u8JlCHUKOBEbgFadP6fS87212gQcDt3ltRQn7C_8qVbG23Hy7uxYSYHFbfs7w1RKWvbgzo9j8ICSazbm-2SKeLvPSnPqhiFcQQ9Md2z11BEALcWv778uvtHU6pLpPxBFsgMbh1CUP3bY7GtSitpba8hPyKP3doCCTUYEa4lADDxjmzRKY-XIzbiEVO82GMHExNucmTB1cTM-hQX3QJoWPDzAHqVIMeAObyQZrJal8_dje-9hUEwZqyAz0nWGewgKeXn3ipx43-MLg';
    
    const realPayload = '{"document":{"header":{"creation_date":"2025-08-04T21:00:57Z","message_id":"6ebaf63f-eeb5-464e-bf3b-a4ec21627c76","receiver":{"fin_id":"ANYENK_CL","fin_id_schema":"SHINKANSEN"},"sender":{"fin_id":"SHINKANSEN","fin_id_schema":"SHINKANSEN"},"shinkansen_message_id":"5190f257-2346-4633-8afa-e15ea7a1800c"},"notifications":[{"amount":"100000.00000","creditor":{"account":"30002590","account_type":"current_account","financial_institution":{"fin_id":"SIMULATED_BANK","fin_id_schema":"SHINKANSEN"},"identification":{"id":"60000159-0","id_schema":"CLID"},"name":"Anyenk"},"currency":"CLP","debtor":{"account":"30002590","account_type":"current_account","financial_institution":{"fin_id":"SIMULATED_BANK","fin_id_schema":"SHINKANSEN"},"identification":{"id":"60000159-0","id_schema":"CLID"},"name":"Anyenk"},"description":"Depositar dinero test0","notification_date":"2025-08-04T21:00:57Z","notification_id":"0c3d19d0-b61d-4e65-b78b-09a9cfbbd27b","notification_type":"payin","original_notification_id":"f5da362c-1134-4e63-95ce-890c780b929e","payment_operator_metadata":null,"referenced_shinkansen_notification_ids":null,"shinkansen_notification_id":"72edbeb6-36b5-4e7b-9914-8601cc94f53d","transaction_accounting_date":"2025-08-04T21:00:57Z","transaction_accounting_id":null,"transaction_date":"2025-08-04T21:00:57Z"}]}}';
    
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

    const verifyResult = await verifySignature({
      jws: realJws,
      payload: realPayload,
      trustedCertificates: [shinkansenCertificate]
    });

    expect(verifyResult.isValid).toBe(true);
    expect(verifyResult.error).toBeUndefined();
  });
});