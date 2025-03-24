.PHONY: test build_test_image

test:
	cargo test -- --nocapture

build_test_image:
	docker build -t my-tailscale:latest . -f Dockerfile.test
