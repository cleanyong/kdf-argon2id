# kdf-argon2id

Simple desktop-friendly CLI to derive an encryption key from a human-memorable
password using Argon2id.

## Usage

Run with defaults (memory 64 MiB, iterations 3, lanes 1, output 32 bytes, fixed shared 16-byte salt):

```
cargo run --release -- \
  --mem-kib 65536 \
  --iterations 3 \
  --lanes 1 \
  --out-len 32
```

You will be prompted (hidden input) for the password. Output shows the Argon2id
parameters, salt (hex), and derived key (hex). To provide your own salt (e.g. for
testing or migration):

```
cargo run --release -- --salt-hex deadbeefcafebabe1122334455667788
```

Adjust `--out-len`, `--mem-kib`, `--iterations`, and `--lanes` as desired.

The derived key is printed in both hex (64 chars for 32-byte AES-256 key) and
base64. For OpenSSL-style CLI AES usage you can copy the hex into `-K` and
provide an IV with `-iv` if needed.
