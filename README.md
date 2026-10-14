# magento-stackgauge-signatures

A versioned, community-reviewable database of content signatures for detecting webshells and
Magecart-style skimmer injections on Magento stores - the "antivirus definitions" consumed by
[StackNuts StackGaugeSecurity](https://github.com/StackNuts/magento-stackgauge-security)'s
`ContentSignatureReporter`, and free for any other tool to use or fork.

MIT licensed, deliberately separate from StackGaugeSecurity's own license: signature *data*
benefits from the widest possible scrutiny and reuse, which is a different goal than the module
code itself has.

## Why a separate repo

A signature set is only as good as how many eyes have checked it for false positives and
gaps - keeping it in its own small, permissively-licensed repo makes that easy: anyone can
read, fork, or contribute to it without needing to touch (or license-agree to) the Magento
module at all. It also means new detections can ship the moment they're validated, independent
of the module's own release cycle.

## Format

```jsonc
{
  "version": "2026.10.1",
  "signatures": [
    {
      "id": "magecart-atob-eval",
      "name": "eval() of base64-decoded script content",
      "severity": "critical",
      "source": "",
      "target": ["cms_content", "design_config"],
      "pattern_type": "literal",
      "pattern": "eval(atob(",
      "description": "...",
      "test_should_match": ["<script>eval(atob('...'))</script>"],
      "test_should_not_match": ["<script>var decoded = atob(x);</script>"]
    }
  ]
}
```

- `severity` is `"critical"` (a confirmed indicator of compromise) or `"warning"` (a heuristic that
  needs human review).
- `source` is the URL of the write-up the signature was drawn from. Leave it as an empty string
  (`""`) if there is no known origin. It is recommended, but not validated.
- `pattern_type` is `"literal"` (a plain substring check) or `"regex"` (a PHP-PCRE pattern with
  delimiters/flags, e.g. `"/pattern/i"`, `preg_match`-compatible). Prefer literal where a plain
  substring suffices.
- `target` is one or more of: `pub_php` (PHP files under `pub/media`/`pub/static`),
  `cms_content` (CMS block/page HTML), `design_config` (admin-editable HTML/JS config values),
  `generated_php` (PHP under `generated/code/`, e.g. interceptor classes a backdoor can rewrite).
  A consuming tool only needs to apply a signature to content of a type it declares a target
  for.
- `test_should_match` / `test_should_not_match` are required for every signature - they're
  enforced by the validation harness below, not just documentation.
- Keep `id` stable once published; bump the top-level `version` whenever the set changes.

## Validation

Every signature must pass `scripts/validate_signatures.php` before it can be merged - this runs
automatically on every push and pull request (see `.github/workflows/validate.yml`), and is the
same check applied before a hand-written signature is merged.

It checks, per signature: required fields and allowed values, no duplicate `id`, a regex
pattern actually compiles, every `test_should_match` sample matches and every
`test_should_not_match` sample doesn't, and - independently of whichever samples the signature's
own author wrote - it matches *nothing* in `corpus/clean/`, a shared, hand-maintained set of
real-looking benign content (a legitimate analytics snippet, a consent banner, ordinary PHP
utility code). That last check matters most: a signature's own negative samples can't prove
anything about content its author never thought to try.

```bash
php scripts/validate_signatures.php
```

## Signing and releasing

The module only accepts a feed whose Ed25519 signature verifies against a public key pinned in
the module itself (`SignatureFeedFetcher::TRUSTED_KEYS`). That's what lets a new signature set
reach every store the moment it lands on `main`, with no module update - while still meaning
nobody who can merely push to this repo (or tamper with the file in transit) can ship rules to
client stores. The SHA-256 sidecar is kept for older module versions, but it only catches a
corrupted download; anyone who can edit `signatures.json` can regenerate it.

Releasing is done by `.github/workflows/sign.yml`. When a change to `signatures.json` lands
on `main` it validates the set, then waits for a maintainer to approve the `feed-release`
GitHub Environment; only then can the job read the signing key (an Environment secret), sign
that exact commit and push `signatures.json.sig` back to `main`. Nothing is signed - and so
nothing reaches client stores - without that approval, even if someone manages to push to
`main` or edit the workflow. Check the commit linked from the run summary before approving.

So a release is:

```bash
php scripts/validate_signatures.php
php scripts/checksum.php write
git add signatures.json signatures.json.sha256 && git commit && git push   # or merge a PR
# then approve the "Sign signatures feed" run in GitHub Actions
```

Signing locally still works (e.g. if Actions is unavailable) - the workflow skips signing when
the pushed signature already verifies:

```bash
php scripts/sign.php sign /path/to/secret.key   # or STACKGAUGE_SIGNING_KEY_FILE
```

The secret key is never committed (`*.key` is gitignored). Public keys live in
`signing-keys/<key id>.pub`.

The module also refuses a feed whose `version` is older than the one it has already cached, so
an old (validly signed) feed can't be replayed to roll detections back - always bump `version`.

To rotate keys: `php scripts/sign.php keygen <new-key-id> <secret-key-file>`, add the new public
key to the module's `TRUSTED_KEYS` alongside the old one and release the module, then start
signing with the new key once stores have updated. Drop the old key from the module later.

## Keeping the set current

Two parts keep the set up to date.

- **Discovery** (`scripts/discover.php`) reads the Sansec research sitemap and the RSS feeds from Sucuri, Malwarebytes and The Hacker News. It keeps Magento-related articles published since its last run, and extracts indicator strings from each one (code blocks, base64 blobs, domains, IP addresses, file names and suspicious calls). It writes them to `data/candidates/`. It never writes signatures.
- **Rule authoring** is done by the `magento-rule-author` skill in `.claude/skills/`. It drafts rules from one source at a time, checks them with `scripts/check_draft.php`, and proposes them on a pull request. Core rules go to `signatures.json`. Domain and IP rules go to `ioc/indicators.json`, where each entry expires after 180 days.

Processed articles are recorded in `data/processed_sources.json`, so each article is read once. That record is committed directly to `main`.

`.github/workflows/validate.yml` runs the validator and the self-tests on every push and pull request. A rule that matches the clean corpus, or that fails its own samples, can't be merged.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests adding or refining signatures are
welcome - include `test_should_match`/`test_should_not_match` samples and make sure
`validate_signatures.php` passes locally first.

## Origins

This project was inspired by [c0defusi0n/securityscanner-signatures](https://github.com/c0defusi0n/securityscanner-signatures),
which showed how a community-maintained, signature-based scanner database could be structured
and shared.

Every signature has a `source` field linking to the write-up it was drawn from. Signatures
without a known origin leave that field blank.

## License

MIT - see [LICENSE](LICENSE).
