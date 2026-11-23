.PHONY: test race fuzz cover lint check

# Everything CI runs, minus the race detector this machine cannot build.
check: lint test

lint:
	gofmt -l .
	go vet ./...

test:
	go test -count=1 ./...

# Needs a C toolchain and CGO_ENABLED=1; on this machine it will refuse.
race:
	go test -race -count=1 ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# Each target for 30s; add T=2m to go longer.
T ?= 30s
fuzz:
	go test ./db/ -run '^$$' -fuzz FuzzPrefixSuccessor -fuzztime $(T)
	go test ./db/ -run '^$$' -fuzz FuzzTableRecordCanonical -fuzztime $(T)
	go test ./db/ -run '^$$' -fuzz FuzzNamespaceBoundsContainTheirKeys -fuzztime $(T)
	go test ./rpc/ -run '^$$' -fuzz FuzzExchange -fuzztime $(T)
	go test ./rpc/ -run '^$$' -fuzz FuzzSessionExchange -fuzztime $(T)
	go test ./rpc/websocket/ -run '^$$' -fuzz FuzzReadMessage -fuzztime $(T)
	go test ./utils/borsh/ -run '^$$' -fuzz FuzzDecodeBijective -fuzztime $(T)
	go test ./utils/borsh/ -run '^$$' -fuzz FuzzValueRoundTrip -fuzztime $(T)
