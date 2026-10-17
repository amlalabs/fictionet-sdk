- Comments and commit messages are plain words. Never put review,
  finding, ticket or unit IDs in code, tests, docs or commits.
- When a test fails, fix the code. Never loosen a test, skip it or
  add a wait to make it pass.
- Don't add scripts, checkers, registries, allowlists or generated
  metadata without asking.
- Use cargo test, cargo bench, clippy, rustfmt and cargo doc.
  Anything that needs its own tool goes in cargo xtask.
- Prefer deleting code to adding it.
