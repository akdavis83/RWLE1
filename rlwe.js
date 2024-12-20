const bigInt = require("big-integer");

// Constants
const n = 1024; // Ring dimension
const q = 40961; // Prime modulus
const W = [...Array(n).keys()].map((i) => (i + 1) % q); // Precomputed twiddle factors
const W_rev = [...Array(n).keys()].map((i) => (q - i - 1) % q); // Reverse twiddle factors

// Parameter Validation
function validateParameters() {
  if (n <= 0 || (n & (n - 1)) !== 0) {
    throw new Error("n must be a power of 2 for FFT compatibility.");
  }
  if (!isPrime(q)) {
    throw new Error("q must be a prime number.");
  }
}

function isPrime(num) {
  if (num < 2) return false;
  for (let i = 2; i * i <= num; i++) {
    if (num % i === 0) return false;
  }
  return true;
}

// Modular Arithmetic Helpers
function mod(x, m) {
  return bigInt(x).mod(m).toJSNumber();
}

function mulMod(a, b, m) {
  return bigInt(a).multiply(b).mod(m).toJSNumber();
}

function addMod(a, b, m) {
  return bigInt(a).add(b).mod(m).toJSNumber();
}

function subMod(a, b, m) {
  return bigInt(a).subtract(b).mod(m).toJSNumber();
}

// FFT Functions
function fftForward(x) {
  let step = 1;
  for (let m = n >> 1; m >= 1; m >>= 1) {
    let index = 0;
    for (let j = 0; j < m; j++) {
      for (let i = j; i < n; i += m << 1) {
        const t0 = addMod(x[i], x[i + m], q);
        const t1 = mulMod(subMod(x[i], x[i + m], q), W[index], q);
        x[i] = t0;
        x[i + m] = t1;
      }
      index = mod(index + (n - step), n);
    }
    step <<= 1;
  }
}

function fftBackward(x) {
  let step = n >> 1;
  for (let m = 1; m < n; m <<= 1) {
    let index = 0;
    for (let j = 0; j < m; j++) {
      for (let i = j; i < n; i += m << 1) {
        const t0 = x[i];
        const t1 = mulMod(x[i + m], W_rev[index], q);
        x[i] = addMod(t0, t1, q);
        x[i + m] = subMod(t0, t1, q);
      }
      index = mod(index + (n - step), n);
    }
    step >>= 1;
  }
}

// Key Exchange Functions
function generateKeyPair() {
  const privateKey = Array.from({ length: n }, () => Math.floor(Math.random() * q));
  const publicKey = privateKey.slice(); // Copy private key
  fftForward(publicKey); // Transform to frequency domain
  return { privateKey, publicKey };
}

function encapsulate(publicKey) {
  const randomPoly = Array.from({ length: n }, () => Math.floor(Math.random() * q));
  const ciphertext = randomPoly.slice(); // Copy randomPoly
  fftForward(ciphertext); // Transform to frequency domain
  const sharedSecret = randomPoly.map((val, i) => mulMod(val, publicKey[i], q));
  return { ciphertext, sharedSecret };
}

function decapsulate(ciphertext, privateKey) {
  const sharedSecret = ciphertext.map((val, i) => mulMod(val, privateKey[i], q));
  fftBackward(sharedSecret); // Transform back to time domain
  return sharedSecret;
}

// Constant-Time Comparison for Security
function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

// Main Execution
try {
  validateParameters();

  // Key Pair Generation
  const { privateKey, publicKey } = generateKeyPair();
  console.log("Private Key:", privateKey);
  console.log("Public Key:", publicKey);

  // Key Encapsulation
  const { ciphertext, sharedSecret: senderSharedSecret } = encapsulate(publicKey);
  console.log("Ciphertext:", ciphertext);
  console.log("Sender's Shared Secret:", senderSharedSecret);

  // Key Decapsulation
  const receiverSharedSecret = decapsulate(ciphertext, privateKey);
  console.log("Receiver's Shared Secret:", receiverSharedSecret);

  // Verify Shared Secrets
  console.log(
    "Shared secrets match (constant time):",
    constantTimeCompare(senderSharedSecret, receiverSharedSecret)
  );
} catch (error) {
  console.error("Error:", error.message);
}
