
lint:
	cargo clippy \
      -- \
      \
      -W clippy::all \
      -W clippy::pedantic \
      \
      -A clippy::module_inception \
      \
      -D warnings


test:
	cargo test --all
	cargo test --all --release
