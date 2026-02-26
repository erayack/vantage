# Coding Conventions

- Follow `rustfmt` defaults.
- Rust naming: files/modules `snake_case`, types/traits `UpperCamelCase`, functions/variables `snake_case`.
- Prefer explicit `Result` propagation with typed errors (`thiserror`) in userspace code.
- Use `tracing` for logs; avoid `println!` in production paths.
- Default policy is `unsafe_code = "forbid"`.
- Narrow exception: `vantage-common` may use minimal, audited `unsafe` needed for shared `aya::Pod` map/event types.
