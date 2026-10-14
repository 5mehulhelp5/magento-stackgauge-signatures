<?php
/**
 * Ed25519 signature over signatures.json, verified by StackGaugeSecurity's SignatureFeedFetcher
 * against public keys pinned in the module itself. The SHA-256 sidecar (see checksum.php) only
 * proves the file wasn't corrupted in transit - anyone able to change signatures.json in this
 * repo can regenerate it too. The signature is what proves a release came from a holder of the
 * private signing key, which is kept offline and never stored in this repo or in CI.
 *
 * signatures.json.sig is JSON: {"algorithm": "ed25519", "key_id": "...", "signature": "<base64>"},
 * the detached signature over the exact bytes of signatures.json. key_id names a public key under
 * signing-keys/<key_id>.pub (base64), so a key can be rotated by publishing a new one alongside
 * the old and pinning both in the module for a release.
 */

declare(strict_types=1);

const SIGNATURE_FILE_NAME = 'signatures.json.sig';
const SIGNING_KEYS_DIR = __DIR__ . '/../../signing-keys';

function signFeed(string $jsonPath, string $secretKeyPath): string
{
    $secretKey = base64_decode(trim((string)file_get_contents($secretKeyPath)), true);
    if ($secretKey === false || strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        throw new RuntimeException("{$secretKeyPath} is not a base64 Ed25519 secret key");
    }

    $keyId = keyIdForPublicKey(sodium_crypto_sign_publickey_from_secretkey($secretKey));
    if ($keyId === null) {
        throw new RuntimeException('That secret key has no matching public key under signing-keys/ - publish it first');
    }

    $signature = sodium_crypto_sign_detached((string)file_get_contents($jsonPath), $secretKey);
    sodium_memzero($secretKey);

    file_put_contents(dirname($jsonPath) . '/' . SIGNATURE_FILE_NAME, json_encode([
        'algorithm' => 'ed25519',
        'key_id' => $keyId,
        'signature' => base64_encode($signature),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

    return $keyId;
}

function verifyFeedSignature(string $jsonPath): bool
{
    $sigPath = dirname($jsonPath) . '/' . SIGNATURE_FILE_NAME;
    $sig = is_file($sigPath) ? json_decode((string)file_get_contents($sigPath), true) : null;

    if (!is_array($sig) || ($sig['algorithm'] ?? null) !== 'ed25519' || !is_string($sig['key_id'] ?? null)) {
        return false;
    }

    $publicKey = publicKey($sig['key_id']);
    $signature = base64_decode((string)($sig['signature'] ?? ''), true);

    return $publicKey !== null
        && $signature !== false
        && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
        && sodium_crypto_sign_verify_detached($signature, (string)file_get_contents($jsonPath), $publicKey);
}

/**
 * Generates a new keypair: the secret key goes to $secretKeyPath (never commit it), the public
 * key to signing-keys/<key id>.pub. Returns the base64 public key, which also has to be added to
 * the module's SignatureFeedFetcher::TRUSTED_KEYS before the module will accept its signatures.
 */
function generateSigningKey(string $keyId, string $secretKeyPath): string
{
    if (!preg_match('/^[a-z0-9-]+$/', $keyId)) {
        throw new RuntimeException('Key id must be lowercase letters, digits and dashes');
    }
    if (file_exists($secretKeyPath) || is_file(SIGNING_KEYS_DIR . "/{$keyId}.pub")) {
        throw new RuntimeException('Refusing to overwrite an existing key');
    }

    $keypair = sodium_crypto_sign_keypair();
    $publicKey = base64_encode(sodium_crypto_sign_publickey($keypair));

    $previousUmask = umask(0077);
    file_put_contents($secretKeyPath, base64_encode(sodium_crypto_sign_secretkey($keypair)) . "\n");
    umask($previousUmask);
    sodium_memzero($keypair);

    if (!is_dir(SIGNING_KEYS_DIR)) {
        mkdir(SIGNING_KEYS_DIR);
    }
    file_put_contents(SIGNING_KEYS_DIR . "/{$keyId}.pub", $publicKey . "\n");

    return $publicKey;
}

function publicKey(string $keyId): ?string
{
    if (!preg_match('/^[a-z0-9-]+$/', $keyId)) {
        return null;
    }

    $path = SIGNING_KEYS_DIR . "/{$keyId}.pub";
    $key = is_file($path) ? base64_decode(trim((string)file_get_contents($path)), true) : false;

    return $key !== false && strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ? $key : null;
}

function keyIdForPublicKey(string $publicKey): ?string
{
    foreach (glob(SIGNING_KEYS_DIR . '/*.pub') ?: [] as $path) {
        $keyId = basename($path, '.pub');
        if (publicKey($keyId) === $publicKey) {
            return $keyId;
        }
    }

    return null;
}
