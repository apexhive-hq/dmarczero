import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';

export type LicenseTier = 'solo' | 'team' | 'enterprise';

export interface LicensePayload {
  product: 'dmarczero';
  tier: Exclude<LicenseTier, 'solo'>;
  holder: string;
  seats: number;
  issuedAt: string;
  expiresAt?: string;
  txHash?: string;
}

export interface SignedLicenseCertificate {
  payload: LicensePayload;
  signature: string; // base64url Ed25519 signature over canonical JSON of payload
}

export interface LicenseVerificationResult {
  valid: boolean;
  tier: LicenseTier;
  holder: string;
  featuresUnlocked: true; // ApexHive 300-point Full Unlock guarantee: NEVER locked
  reason: string;
}

export const APEXHIVE_BASE_USDC_ADDRESS = '0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206';

/**
 * Default ApexHive Labs Ed25519 public key (SPKI PEM).
 * Callers can override with a custom publicKeyPem in tests or enterprise deployments.
 */
export const DEFAULT_APEXHIVE_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEArz/+yUqh9Alo5B2DPD23q2vbvAuPPL5m1zqtHg66cA0=
-----END PUBLIC KEY-----`;

export function canonicalizePayload(payload: LicensePayload): string {
  const ordered: Record<string, unknown> = {
    product: payload.product,
    tier: payload.tier,
    holder: payload.holder,
    seats: payload.seats,
    issuedAt: payload.issuedAt
  };
  if (payload.expiresAt !== undefined) ordered.expiresAt = payload.expiresAt;
  if (payload.txHash !== undefined) ordered.txHash = payload.txHash;
  return JSON.stringify(ordered);
}

/**
 * Helper for signing certificates with an Ed25519 private key (used by issuer tooling & tests).
 */
export function signLicensePayload(payload: LicensePayload, privateKeyPem: string): SignedLicenseCertificate {
  const canonical = Buffer.from(canonicalizePayload(payload), 'utf8');
  const sig = crypto.sign(null, canonical, privateKeyPem);
  return {
    payload,
    signature: sig.toString('base64url')
  };
}

/**
 * Offline Ed25519 verification for optional Team/Enterprise commercial certificates.
 * Honors the ApexHive Dual Source-Available Solo-Free guarantee: featuresUnlocked is ALWAYS true.
 */
export function verifyLicenseCertificate(
  cert: SignedLicenseCertificate,
  publicKeyPem: string = DEFAULT_APEXHIVE_PUBLIC_KEY_PEM,
  now: Date = new Date()
): LicenseVerificationResult {
  if (!cert || !cert.payload || typeof cert.signature !== 'string') {
    return {
      valid: false,
      tier: 'solo',
      holder: 'Solo User',
      featuresUnlocked: true,
      reason: 'Malformed license certificate; running in full-featured Solo mode (0 USDC)'
    };
  }

  if (cert.payload.product !== 'dmarczero') {
    return {
      valid: false,
      tier: 'solo',
      holder: 'Solo User',
      featuresUnlocked: true,
      reason: 'Certificate is not issued for dmarczero; running in full-featured Solo mode'
    };
  }

  if (cert.payload.tier !== 'team' && cert.payload.tier !== 'enterprise') {
    return {
      valid: false,
      tier: 'solo',
      holder: 'Solo User',
      featuresUnlocked: true,
      reason: 'Unknown commercial tier; running in full-featured Solo mode'
    };
  }

  if (cert.payload.expiresAt) {
    const exp = new Date(cert.payload.expiresAt);
    if (!Number.isNaN(exp.getTime()) && exp.getTime() < now.getTime()) {
      return {
        valid: false,
        tier: 'solo',
        holder: cert.payload.holder,
        featuresUnlocked: true,
        reason: `Commercial certificate expired on ${cert.payload.expiresAt}; all features remain unlocked`
      };
    }
  }

  try {
    const canonical = Buffer.from(canonicalizePayload(cert.payload), 'utf8');
    const sigBuf = Buffer.from(cert.signature, 'base64url');
    const ok = crypto.verify(null, canonical, publicKeyPem, sigBuf);
    if (!ok) {
      return {
        valid: false,
        tier: 'solo',
        holder: 'Solo User',
        featuresUnlocked: true,
        reason: 'Ed25519 signature verification failed; running in full-featured Solo mode'
      };
    }

    return {
      valid: true,
      tier: cert.payload.tier,
      holder: cert.payload.holder,
      featuresUnlocked: true,
      reason: `Valid ${cert.payload.tier.toUpperCase()} commercial license for ${cert.payload.holder}`
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      tier: 'solo',
      holder: 'Solo User',
      featuresUnlocked: true,
      reason: `Signature verification error (${msg}); running in full-featured Solo mode`
    };
  }
}

export async function verifyLicenseFile(
  filePath: string,
  publicKeyPem: string = DEFAULT_APEXHIVE_PUBLIC_KEY_PEM
): Promise<LicenseVerificationResult> {
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw) as SignedLicenseCertificate;
  return verifyLicenseCertificate(parsed, publicKeyPem);
}
