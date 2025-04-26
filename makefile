OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
PROTOCOLS := ip icmp tcp dns ntp smtp snmp http tls 

.PHONY: windows linux
all: init windows linux

init:
	@echo "Initializing project structure..."
	@for proto in $(PROTOCOLS); do \
		mkdir -p bin; \
		mkdir -p internal/$$proto; \
		mkdir -p cmd/$$proto; \
	done
	@echo "Project structure initialized."
	@test -f go.mod || go mod init GoTrafficGen
	go mod tidy

windows:
	@for proto in $(PROTOCOLS); do \
		$(MAKE) build OS=windows PROTO=$$proto; \
	done

linux:
	@for proto in $(PROTOCOLS); do \
		$(MAKE) build OS=linux PROTO=$$proto; \
	done

build:
	@echo "Building for $(OS) protocol $(PROTO)..."
	GOOS=$(OS) GOARCH=amd64 go build -o bin/$(PROTO)tg$(if $(filter windows,$(OS)),.exe,) ./cmd/$(PROTO)
	@echo "Build complete for $(OS) protocol $(PROTO)."