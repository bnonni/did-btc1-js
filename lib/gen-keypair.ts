import { randomBytes } from 'crypto';
import { createHash } from 'crypto';
import * as secp256k1 from '@noble/secp256k1';
import { bech32 } from 'bech32';

// Helper function to perform SHA256 hash followed by RIPEMD160 hash
function hash160(buffer: Buffer): Buffer {
  const sha256 = createHash('sha256').update(buffer).digest();
  return createHash('ripemd160').update(sha256).digest();
}

// Generate a secp256k1 key pair
async function generateKeyPair(): Promise<{ privateKey: string; address: string }> {
  // Generate a random 32-byte private key
  const privateKey = randomBytes(32);

  // Get the corresponding public key
  const publicKey = secp256k1.getPublicKey(privateKey, true); // Compressed public key

  // Perform Hash160 (SHA256 + RIPEMD160) on the public key
  const publicKeyHash = hash160(Buffer.from(publicKey));

  // Prepare SegWit program (version byte 0x00 + public key hash)
  const segwitVersion = 0x01;
  const program = [segwitVersion, ...Array.from(publicKeyHash)];

  // Convert program to 5-bit words
  const words = bech32.toWords(Buffer.from(program));

  // Encode into Bech32 address with "bc" prefix (mainnet)
  const address = bech32.encode('bc', words);

  return {
    privateKey : Buffer.from(privateKey).toString('hex'),
    address,
  };}

// Generate and log the key pair
generateKeyPair()
  .then((keyPair) => {
    console.log('Private Key:', keyPair.privateKey);
    console.log('Bitcoin Address:', keyPair.address);
  })
  .catch((error) => console.error('Error generating key pair:', error));
