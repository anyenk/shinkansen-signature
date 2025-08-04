import { flattenedVerify, importX509, importPKCS8, FlattenedSign } from 'jose';
import * as forge from 'node-forge';

export interface VerifySignatureOptions {
  jws: string;
  payload: string;
  trustedCertificates: string[];
}

export interface VerificationResult {
  isValid: boolean;
  error?: string;
}

export interface CreateSignatureOptions {
  payload: string;
  privateKey: string;
  certificate: string;
}

export interface SignatureResult {
  signature: string;
  error?: string;
}

export async function verifySignature(options: VerifySignatureOptions): Promise<VerificationResult> {
  try {
    const { jws, payload, trustedCertificates } = options;

    // Parse JWS header to extract certificate and algorithm
    const headerB64 = jws.split('.')[0];
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

    // Verify algorithm is PS256
    if (header.alg !== 'PS256') {
      return { isValid: false, error: 'Invalid algorithm. Expected PS256' };
    }

    // Extract certificate from x5c header
    if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
      return { isValid: false, error: 'Missing x5c certificate in JWS header' };
    }

    const certDer = header.x5c[0];
    const certPem = `-----BEGIN CERTIFICATE-----\n${certDer.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;

    // Validate certificate against trusted whitelist
    const isTrusted = trustedCertificates.some(trustedCert => {
      const trustedPem = trustedCert.startsWith('-----BEGIN CERTIFICATE-----') 
        ? trustedCert 
        : `-----BEGIN CERTIFICATE-----\n${trustedCert.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
      return certPem === trustedPem;
    });

    if (!isTrusted) {
      return { isValid: false, error: 'Certificate not in trusted whitelist' };
    }

    // Verify certificate is not expired
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      const now = new Date();
      if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
        return { isValid: false, error: 'Certificate is expired or not yet valid' };
      }
    } catch (certError) {
      return { isValid: false, error: 'Invalid certificate format' };
    }

    // Import public key from certificate
    const publicKey = await importX509(certPem, 'PS256');

    // For detached signature with b64=false, we need to handle verification manually
    // The detached signature format is: header..signature
    const [protectedHeader, , signature] = jws.split('.');
    
    // Create a flattened JWS with the payload for verification
    const flattenedJws = {
      protected: protectedHeader,
      payload: payload, // Raw payload, not base64url encoded due to b64=false
      signature: signature
    };

    // Use flattenedVerify with the complete JWS
    await flattenedVerify(flattenedJws, publicKey, {
      algorithms: ['PS256']
    });

    return { isValid: true };

  } catch (error) {
    return { 
      isValid: false, 
      error: error instanceof Error ? error.message : 'Unknown verification error' 
    };
  }
}

export async function createSignature(options: CreateSignatureOptions): Promise<SignatureResult> {
  try {
    const { payload, privateKey, certificate } = options;

    // Import private key first
    let privateKeyObj;
    try {
      const privateKeyPem = privateKey.startsWith('-----BEGIN PRIVATE KEY-----') 
        ? privateKey 
        : `-----BEGIN PRIVATE KEY-----\n${privateKey.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;
      
      privateKeyObj = await importPKCS8(privateKeyPem, 'PS256');
    } catch (keyError) {
      return { signature: '', error: 'Invalid private key format' };
    }

    // Convert certificate to DER format for x5c header
    let certDer: string;
    try {
      const certPem = certificate.startsWith('-----BEGIN CERTIFICATE-----') 
        ? certificate 
        : `-----BEGIN CERTIFICATE-----\n${certificate.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
      
      const cert = forge.pki.certificateFromPem(certPem);
      const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
      certDer = forge.util.encode64(derBytes);
    } catch (certError) {
      return { signature: '', error: 'Invalid certificate format' };
    }

    // Create JWS protected header
    const protectedHeader = {
      alg: 'PS256',
      b64: false,
      crit: ['b64'],
      x5c: [certDer]
    };

    // Create JWS with detached payload using FlattenedSign
    const jws = await new FlattenedSign(new TextEncoder().encode(payload))
      .setProtectedHeader(protectedHeader)
      .sign(privateKeyObj);

    // Return detached signature format: {protected_header}..{signature}
    const detachedSignature = `${jws.protected}..${jws.signature}`;

    return { signature: detachedSignature };

  } catch (error) {
    return { 
      signature: '', 
      error: error instanceof Error ? error.message : 'Unknown signing error' 
    };
  }
}

export default {
  verifySignature,
  createSignature,
};