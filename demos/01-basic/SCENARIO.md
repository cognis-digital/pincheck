# Demo 01 — Basic network-security-config validation

This demo runs PINCHECK against a deliberately weak Android
`network_security_config.xml` to show what a failing CI gate looks like.

## Input

`network_security_config.xml` declares:

- a `base-config` that **permits cleartext traffic** (`cleartextTrafficPermitted="true"`),
- a `domain-config` for `api.example.com` with a `<pin-set>` that has
  **only one pin** (no backup pin) and an **expiration in the past** (`2021-01-01`),
- a second `domain-config` for `cdn.example.com` that trusts **user-added CAs**
  (`<certificates src="user"/>`) and has **no `<pin-set>`** at all.

## Run it

```bash
python -m pincheck check demos/01-basic/network_security_config.xml
# JSON for CI:
python -m pincheck check demos/01-basic/network_security_config.xml --format json
```

## Expected result

The tool reports multiple findings and **fails the gate (exit code 1)**:

| Severity | Code              | Why |
|----------|-------------------|-----|
| HIGH     | `BASE_CLEARTEXT`  | base-config allows unencrypted HTTP |
| HIGH     | `EXPIRED_PIN_SET` | the `api.example.com` pin-set expired on 2021-01-01 |
| MEDIUM   | `NO_BACKUP_PIN`   | `api.example.com` has only one pin |
| HIGH     | `USER_TRUST_ANCHOR` | `cdn.example.com` trusts user-added CAs |
| HIGH     | `MISSING_PIN_SET` | `cdn.example.com` has no pin-set |

`max_severity` is `HIGH` and `failed` is `true`, so the command exits non-zero,
blocking a CI pipeline until pinning is fixed.
