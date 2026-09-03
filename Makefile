.DEFAULT_GOAL := all

BUILD_DIR ?= build
PRIVATE_KEY := .tmp.pem
SEED_TEMPLATE := lib/src/encrypter_seed.cpp.in
SEED_SOURCE := lib/src/encrypter_seed.cpp

.PHONY: all build test clean

all: build test

build: $(SEED_SOURCE)
	cmake -S . -B "$(BUILD_DIR)"
	cmake --build "$(BUILD_DIR)"

test: build
	ctest --test-dir "$(BUILD_DIR)" --output-on-failure

clean:
	@case "$(BUILD_DIR)" in \
		""|/|.|..) echo "Refusing to remove unsafe BUILD_DIR: $(BUILD_DIR)" >&2; exit 1 ;; \
	esac
	cmake -E remove_directory "$(BUILD_DIR)"

$(PRIVATE_KEY):
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$@"

$(SEED_SOURCE): $(SEED_TEMPLATE) $(PRIVATE_KEY)
	@{ \
		sed -n '1,$$p' "$(SEED_TEMPLATE)"; \
		awk '!/^-----/ { print $$0 "\\" }' "$(PRIVATE_KEY)"; \
		printf '%s\n' '";' '        return seed_data;' '}' '}'; \
	} > "$@.tmp"
	@mv "$@.tmp" "$@"
