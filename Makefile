test:
	@cargo test --quiet -- --nocapture

hello:
	@cargo test --quiet parse_hello -- --nocapture
