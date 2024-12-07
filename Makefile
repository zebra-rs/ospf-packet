test:
	@cargo test --quiet -- --nocapture

lsp:
	@RUST_BACKTRACE=1 cargo test --quiet parse_l1lsp_test_1 -- --nocapture

hello:
	@cargo test --quiet parse_l1hello_test -- --nocapture

csnp:
	@cargo test --quiet parse_csnp -- --nocapture

psnp:
	@cargo test --quiet parse_psnp -- --nocapture
