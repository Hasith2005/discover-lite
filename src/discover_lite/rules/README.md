# Vendored rules

`gitleaks.toml` is the default rule set of [gitleaks](https://github.com/gitleaks/gitleaks), copied unchanged from tag `v8.30.1` (`config/gitleaks.toml`). It is MIT licensed; the licence is in `LICENSE-gitleaks`.

`secret_rules.py` reads it to recognise vendor key formats (Stripe, GitHub, AWS, Slack and about 200 more), so this project does not keep its own list of key prefixes.

To update: download `config/gitleaks.toml` from a newer gitleaks release, replace this file, note the new tag above, and run the tests.
