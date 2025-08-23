import bcrypt from 'bcryptjs';

// Lazy-load argon2 to avoid build-time dependency when not installed
let __argon2: any = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  __argon2 = require('argon2');
} catch {
  __argon2 = null;
}

// Centralized password hashing/verification
// - New hashes use Argon2id
// - Verification supports both Argon2 and legacy bcrypt hashes

// Tuned but conservative defaults to avoid excessive CPU/RAM on small servers
const ARGON2_OPTIONS: any = {
  type: __argon2 ? __argon2.argon2id : 2, // argon2id
  memoryCost: 19456, // ~19MB
  timeCost: 2,
  parallelism: 1,
};

export function isArgon2Hash(stored: string | undefined | null): boolean {
  const s = String(stored || '');
  return s.startsWith('$argon2');
}

export async function hashPassword(plain: string): Promise<string> {
  if (__argon2) {
    return await __argon2.hash(plain, ARGON2_OPTIONS);
  }
  // Fallback to bcrypt when argon2 module is unavailable
  return await bcrypt.hash(plain, 10);
}

export async function verifyPassword(plain: string, storedHash: string): Promise<boolean> {
  if (!storedHash) return false;
  try {
    if (isArgon2Hash(storedHash) && __argon2) {
      return await __argon2.verify(storedHash, plain, ARGON2_OPTIONS);
    }
    // Fallback for legacy bcrypt hashes (e.g., $2a$ / $2b$ / $2y$)
    if (/^\$2[aby]\$/.test(storedHash)) {
      return await bcrypt.compare(plain, storedHash);
    }
    // Unknown prefix: try both (best-effort)
    try { if (__argon2 && await __argon2.verify(storedHash, plain, ARGON2_OPTIONS)) return true; } catch {}
    try { if (await bcrypt.compare(plain, storedHash)) return true; } catch {}
    return false;
  } catch {
    return false;
  }
}
