.PHONY: test build clean

test:
	cd go && go test ./...
	cd rust && cargo test

build:
	cd go && go build ./...
	cd rust && cargo build --release

clean:
	cd rust && cargo clean
