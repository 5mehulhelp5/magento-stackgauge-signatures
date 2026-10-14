<?php
/**
 * CLI for the signatures.json Ed25519 signature (see lib/signing.php).
 *
 *   php scripts/sign.php sign <secret-key-file>     sign signatures.json (run after every change, before pushing)
 *   php scripts/sign.php verify                     exit non-zero unless the signature is valid (run by validate.yml)
 *   php scripts/sign.php keygen <key-id> <secret-key-file>   create a new signing key
 *
 * The secret key file can also be given via STACKGAUGE_SIGNING_KEY_FILE.
 */

declare(strict_types=1);

require __DIR__ . '/lib/signing.php';

$json = __DIR__ . '/../signatures.json';
$secretKeyFile = static fn(int $index): string => $argv[$index] ?? (getenv('STACKGAUGE_SIGNING_KEY_FILE') ?: '');

try {
    switch ($argv[1] ?? '') {
        case 'sign':
            $keyFile = $secretKeyFile(2);
            if ($keyFile === '') {
                throw new RuntimeException('Pass the secret key file, or set STACKGAUGE_SIGNING_KEY_FILE');
            }
            $keyId = signFeed($json, $keyFile);
            echo 'Wrote ' . SIGNATURE_FILE_NAME . " (key {$keyId})\n";
            exit(0);
        case 'verify':
            if (verifyFeedSignature($json)) {
                echo "Signature is valid for signatures.json.\n";
                exit(0);
            }
            fwrite(STDERR, SIGNATURE_FILE_NAME . " is missing or does not verify. Sign it: php scripts/sign.php sign <secret-key-file>\n");
            exit(1);
        case 'keygen':
            [$keyId, $keyFile] = [$argv[2] ?? '', $secretKeyFile(3)];
            if ($keyId === '' || $keyFile === '') {
                throw new RuntimeException('Usage: php scripts/sign.php keygen <key-id> <secret-key-file>');
            }
            $publicKey = generateSigningKey($keyId, $keyFile);
            echo "Secret key written to {$keyFile} - keep it offline, never commit it.\n";
            echo "Public key signing-keys/{$keyId}.pub: {$publicKey}\n";
            echo "Add it to StackGaugeSecurity's SignatureFeedFetcher::TRUSTED_KEYS as '{$keyId}'.\n";
            exit(0);
        default:
            fwrite(STDERR, "Usage: php scripts/sign.php sign <secret-key-file> | verify | keygen <key-id> <secret-key-file>\n");
            exit(2);
    }
} catch (RuntimeException $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}
