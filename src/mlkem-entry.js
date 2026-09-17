// CipherDrop — ML-KEM-512 browser entry point
// Wraps @noble/post-quantum's pure-JS FIPS 203 implementation and exposes
// it as a single global (window.MLKEM512) so the rest of the frontend can
// stay dependency-free vanilla JS, with no runtime CDN fetch.
import { ml_kem512 } from '@noble/post-quantum/ml-kem.js';

window.MLKEM512 = {
  /** Generate a fresh (encapsulation key, decapsulation key) pair. */
  keygen() {
    const { publicKey, secretKey } = ml_kem512.keygen();
    return { ek: publicKey, dk: secretKey };
  },
  /** Encapsulate a fresh shared secret to an encapsulation key (ek). */
  encapsulate(ek) {
    const { cipherText, sharedSecret } = ml_kem512.encapsulate(ek);
    return { kemCipherText: cipherText, sharedSecret };
  },
  /** Recover the shared secret from KEM ciphertext + decapsulation key (dk). */
  decapsulate(kemCipherText, dk) {
    return ml_kem512.decapsulate(kemCipherText, dk);
  },
};
