.PHONE: help
help:
	@echo "Read README.md first"

.PHONE: install-test-deps
install-test-deps:
	yum install -y iptables iputils gcc bind-utils tar llvm yum-utils curl iptables openssl iproute ipset jq perl openssl-devel clang

.PHONE: run-test
run-test: install-test-deps
	yum-builddep -y --skip-unavailable ./trusted-network-gateway.spec

	./tng-testsuite/run-test.sh

.PHONE: run-test-coverage
run-test-coverage: install-test-deps
	yum-builddep -y --skip-unavailable ./trusted-network-gateway.spec

	./tng-testsuite/run-test.sh --coverage

.PHONY: run-test-on-bin
run-test-on-bin: install-test-deps
	cargo build --no-default-features --features on-bin --package tng-testsuite --tests
	cargo test --no-default-features --features on-bin --package tng-testsuite --tests -- --nocapture


.PHONY: run-test-on-podman
run-test-on-podman: install-test-deps
	cargo build --no-default-features --features on-podman --package tng-testsuite --tests
	cargo test --no-default-features --features on-podman --package tng-testsuite --tests -- --nocapture


VERSION 	:= $(shell grep '^version' ./Cargo.toml | awk -F' = ' '{print $$2}' | tr -d '"')

# Version components for bumping
MAJOR := $(shell echo $(VERSION) | awk -F. '{print $$1}')
MINOR := $(shell echo $(VERSION) | awk -F. '{print $$2}')
PATCH := $(shell echo $(VERSION) | awk -F. '{print $$3}')

# Calculate new versions
NEW_VERSION_MAJOR := $(shell echo $$(( $(MAJOR) + 1 ))).0.0
NEW_VERSION_MINOR := $(MAJOR).$(shell echo $$(( $(MINOR) + 1 ))).0
NEW_VERSION_PATCH := $(MAJOR).$(MINOR).$(shell echo $$(( $(PATCH) + 1 )))

# Function to update Cargo.toml version
define update-cargo-toml
	@sed -i 's/^version = "$(VERSION)"/version = "$(1)"/' Cargo.toml
endef

# Function to update buildspec.yml version
define update-buildspec-yml
	@sed -i -E 's/(tags: \[\[)[0-9]+\.[0-9]+\.[0-9]+(, latest\]\])/\1$(1)\2/' APPLICATION/tng/buildspec.yml
endef

# Function to update pyproject.toml version (Python SDK)
define update-pyproject-toml
	@sed -i 's/^version = "$(VERSION)"/version = "$(1)"/' tng-python/pyproject.toml
endef

# Function to update Cargo.lock
define update-cargo-lock
	@cargo update --workspace --offline 2>/dev/null || cargo update --workspace
endef

# Function to get git info
define get-git-info
	$(eval AUTHOR := $(shell git log -1 --pretty=format:"%an <%ae>"))
endef

# Function to determine last tag
# $(1) = expected previous version tag (e.g., v2.4.0)
define determine-last-tag
	$(eval EXPECTED_TAG := $(1))
	$(eval TAG_EXISTS := $(shell git tag -l "$(EXPECTED_TAG)"))
	$(eval LAST_TAG := $(if $(TAG_EXISTS),$(EXPECTED_TAG),$(shell git tag --sort=-version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1)))
endef

# Function to write commits to file for RPM (uses -)
define write-commits-to-file
	@git log $(LAST_TAG)..HEAD --pretty=format:"- %s" --no-merges > $(1) 2>/dev/null || echo "- Version bump to $(2)" > $(1)
endef

# Function to update RPM spec version and changelog
define update-rpm-spec
	@# Update Version field in spec file (matches any version number)
	@sed -i 's/^Version: .*/Version: $(1)/' trusted-network-gateway.spec
	$(eval RPM_DATE := $(shell LC_ALL=C date +"%a %b %d %Y"))
	@echo "* $(RPM_DATE) $(AUTHOR) - $(1)-1" > /tmp/rpm_changelog_entry.txt
	$(call write-commits-to-file,/tmp/rpm_commits.txt,$(1))
	@cat /tmp/rpm_commits.txt >> /tmp/rpm_changelog_entry.txt
	@echo "" >> /tmp/rpm_changelog_entry.txt
	@echo "" >> /tmp/rpm_changelog_entry.txt
	@awk '/^%changelog/{print; while((getline line < "/tmp/rpm_changelog_entry.txt") > 0) print line; close("/tmp/rpm_changelog_entry.txt"); next} {print}' trusted-network-gateway.spec > trusted-network-gateway.spec.new && mv trusted-network-gateway.spec.new trusted-network-gateway.spec
	@rm -f /tmp/rpm_changelog_entry.txt /tmp/rpm_commits.txt
endef

# Main bump version function
# $(1) = version type (major/minor/patch)
# $(2) = new version number
# $(3) = expected previous version tag (e.g., v2.4.0)
define bump-version-internal
	@echo "Bumping $(1) version: $(VERSION) -> $(2)"
	$(call update-cargo-toml,$(2))
	$(call update-pyproject-toml,$(2))
	@echo "New version: $(2)"
	$(call update-cargo-lock)
	$(call update-buildspec-yml,$(2))
	@echo "Updated APPLICATION/tng/buildspec.yml"
	@echo "Updated tng-python/pyproject.toml"
	$(call get-git-info)
	$(call determine-last-tag,$(3))
	@echo "Using last tag: $(LAST_TAG)"
	@echo "Updating RPM spec version and changelog..."
	$(call update-rpm-spec,$(2))
	@echo "Version bump complete. New version: $(2)"
	@echo "Changes made:"
	@echo "  - Updated Cargo.toml"
	@echo "  - Updated Cargo.lock"
	@echo "  - Updated APPLICATION/tng/buildspec.yml"
	@echo "  - Updated tng-python/pyproject.toml"
	@echo "  - Updated RPM spec version and changelog"
	@echo ""
	@echo "If it is ok to commit, run the following commands:"
	@echo "  git add ."
	@echo "  git commit -m \"Bump $(1) version to $(2)\""
	@echo "  git tag -a v$(2) -m \"Bump $(1) version to $(2)\""
	@echo "  git push origin v$(2)"
endef

# Bump major version (2.4.0 -> 3.0.0)
.PHONY: bump-version-major
bump-version-major:
	$(call bump-version-internal,major,$(NEW_VERSION_MAJOR),v$(VERSION))

# Bump minor version (2.4.0 -> 2.5.0)
.PHONY: bump-version-minor
bump-version-minor:
	$(call bump-version-internal,minor,$(NEW_VERSION_MINOR),v$(VERSION))

# Bump patch version (2.4.0 -> 2.4.1)
.PHONY: bump-version-patch
bump-version-patch:
	$(call bump-version-internal,patch,$(NEW_VERSION_PATCH),v$(VERSION))

.PHONE: create-tarball
create-tarball:
	rm -rf /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/ && mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/

	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/
	cargo +nightly-2025-07-07 vendor --locked --manifest-path ./Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ | tee /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/config.toml

	sed -i 's;^.*directory = .*/vendor/.*$$;directory = "vendor";g' /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/config.toml

	# sanity check on cargo vendor
	@grep "source.crates-io" /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/config.toml >/dev/null || (echo "cargo vendor failed, please check /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/config.toml"; exit 1)

	# remove unused files
	find /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/windows*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	find /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/winapi*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/windows*/lib/*.a
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/winapi*/lib/*.a
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/winapi*/lib/*.lib
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/windows*/lib/*.lib

	# patch on some crate that cannot be resolved in cargo 1.75
	# remove crates which need to be patched
	rm -rf /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm-*
	rm -rf /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ws_stream_wasm-*
	rm -rf /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm_proc-*
	# patch for tokio_with_wasm
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm-fake/
	printf '[package]\nedition = "2021"\nname = "tokio_with_wasm"\nversion = "0.8.6"\n\n[lib]\n\n[features]\nrt=[]\nmacros=[]\ntime=[]' > /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm-fake/Cargo.toml
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm-fake/src/
	touch /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm-fake/src/lib.rs
	echo '{"files":{}}' > /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm-fake/.cargo-checksum.json
	# patch for ws_stream_wasm
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ws_stream_wasm-fake/
	printf '[package]\nedition = "2021"\nname = "ws_stream_wasm"\nversion = "0.7.5"\n\n[lib]' > /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ws_stream_wasm-fake/Cargo.toml
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ws_stream_wasm-fake/src/
	touch /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ws_stream_wasm-fake/src/lib.rs
	echo '{"files":{}}' > /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ws_stream_wasm-fake/.cargo-checksum.json
	# patch for tokio_with_wasm_proc
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm_proc-fake/
	printf '[package]\nedition = "2021"\nname = "tokio_with_wasm_proc"\nversion = "0.8.6"\n\n[lib]' > /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm_proc-fake/Cargo.toml
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm_proc-fake/src/
	touch /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm_proc-fake/src/lib.rs
	echo '{"files":{}}' > /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/tokio_with_wasm_proc-fake/.cargo-checksum.json

	# copy source code to src/
	git clone --no-hardlinks . /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src/
	# apply uncommitted changes (staged + unstaged) to the cloned copy
	git diff --binary HEAD | git -C /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src apply --binary --allow-empty
	# copy untracked (new) files that are not ignored
	if [ -n "$$(git ls-files --others --exclude-standard)" ] ; then git ls-files --others --exclude-standard -z | xargs -0 tar -c -f - | tar -x -f - -C /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src/ ; fi

	# delete all checksum (this is required due to previous patch work)
	sed -i 's/checksum = ".*//g' /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src/Cargo.lock

	# create tarball
	tar -czf /tmp/trusted-network-gateway-${VERSION}-vendored-source.tar.gz -C /tmp/trusted-network-gateway-tarball/ trusted-network-gateway-${VERSION}

	@echo "Tarball generated:" /tmp/trusted-network-gateway-${VERSION}-vendored-source.tar.gz


.PHONE: bin-build
bin-build:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release --features 'builtin-as-tdx-rust'

.PHONE: tng-hook-build
tng-hook-build:
	cargo build --release -p tng-hook-cdylib

.PHONE: rpm-build
rpm-build:
	# setup build tree rpmdevtools
	rpmdev-setuptree

	# copy sources
	cp /tmp/trusted-network-gateway-${VERSION}-vendored-source.tar.gz ~/rpmbuild/SOURCES/

	# install build dependencies
	yum-builddep -y --skip-unavailable ./trusted-network-gateway.spec
	
	# build
	rpmbuild -ba ./trusted-network-gateway.spec --define 'with_rustup 1'
	@echo "RPM package is:" ~/rpmbuild/RPMS/*/trusted-network-gateway-*

.PHONE: rpm-build-in-docker
rpm-build-in-docker:
	# copy sources
	mkdir -p ~/rpmbuild/SOURCES/
	cp /tmp/trusted-network-gateway-${VERSION}-vendored-source.tar.gz ~/rpmbuild/SOURCES/

	docker run --rm -v ~/rpmbuild:/root/rpmbuild -v .:/code --workdir=/code alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest bash -x -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none ; source \"\$$HOME/.cargo/env\" ; sed -i -E 's|https?://mirrors.cloud.aliyuncs.com/|https://mirrors.aliyun.com/|g' /etc/yum.repos.d/*.repo ; yum install -y rpmdevtools yum-utils; rpmdev-setuptree ; yum-builddep -y --skip-unavailable ./trusted-network-gateway.spec ; rpmbuild -ba ./trusted-network-gateway.spec --define 'with_rustup 1'"

.PHONE: rpm-install
rpm-install: rpm-build
	yum remove trusted-network-gateway -y
	ls -t ~/rpmbuild/RPMS/*/trusted-network-gateway-* | head -n 1 | xargs yum install -y

.PHONE: update-rpm-tree
update-rpm-tree:
	# copy sources
	rm -f ../rpm-tree-tng/trusted-network-gateway-*.tar.gz
	cp /tmp/trusted-network-gateway-${VERSION}-vendored-source.tar.gz ../rpm-tree-tng/
	cp ./trusted-network-gateway.spec ../rpm-tree-tng/

.PHONE: docker-build
docker-build:
	docker build -t tng:${VERSION} .

.PHONY: docker-build-ubuntu
docker-build-ubuntu:
	docker build -t tng:${VERSION}-ubuntu2404 -f Dockerfile.ubuntu2404 .

.PHONE: install-wasm-build-dependencies
install-wasm-build-dependencies:
	if ! command -v wasm-pack >/dev/null; then \
		cargo +nightly-2025-07-07 install wasm-pack@0.14.0 --locked ; \
	fi
	if ! rustup component list --toolchain nightly-2025-07-07-x86_64-unknown-linux-gnu | grep rust-src | grep installed >/dev/null; then \
		rustup component add rust-src --toolchain nightly-2025-07-07-x86_64-unknown-linux-gnu ; \
	fi

define WASM_PATCH_PACKAGE_JSON =
	@echo "Patching package.json ..."
	if ! command -v jq >/dev/null; then yum install -y jq ; fi
	rm -f tng-wasm/pkg/package.json.bak && \
		cp tng-wasm/pkg/package.json tng-wasm/pkg/package.json.bak && \
		jq '.name = "@inclavare-containers/tng" | .publishConfig = { "registry": "https://npm.pkg.github.com/", "access": "public" }' tng-wasm/pkg/package.json.bak > tng-wasm/pkg/package.json
endef

.PHONE: wasm-build-release
wasm-build-release: install-wasm-build-dependencies
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --release --target web ./tng-wasm -Z build-std=std,panic_abort
	$(WASM_PATCH_PACKAGE_JSON)

.PHONE: wasm-build-debug
wasm-build-debug: install-wasm-build-dependencies
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --dev --target web ./tng-wasm -Z build-std=std,panic_abort
	$(WASM_PATCH_PACKAGE_JSON)

.PHONE: wasm-pack-release
wasm-pack-release: wasm-build-release
	wasm-pack pack
	@echo 'Now you can install with "npm install <tar.gz path>"'

.PHONE: wasm-pack-debug
wasm-pack-debug: wasm-build-debug
	wasm-pack pack
	@echo 'Now you can install with "npm install <tar.gz path>"'

.PHONE: wasm-unit-test
wasm-unit-test: wasm-unit-test-chrome

.PHONE: wasm-unit-test-chrome
wasm-unit-test-chrome: install-wasm-build-dependencies
	if ! command -v google-chrome; then echo -e '[google-chrome]\nname=google-chrome\nbaseurl=https://dl.google.com/linux/chrome/rpm/stable/x86_64\nenabled=1\ngpgcheck=1\ngpgkey=https://dl.google.com/linux/linux_signing_key.pub' | tee /etc/yum.repos.d/google-chrome.repo; yum install google-chrome-stable -y ; fi
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --chrome ./tng-wasm -Z build-std=std,panic_abort -- --nocapture

.PHONE: wasm-unit-test-firefox
wasm-unit-test-firefox: install-wasm-build-dependencies
	if ! command -v firefox; then yum install -y firefox ; fi
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --firefox ./tng-wasm -Z build-std=std,panic_abort -- --nocapture

.PHONE: wasm-integration-test
wasm-integration-test: wasm-build-debug install-test-deps
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 cargo test --no-default-features --features on-source-code,js-sdk --package tng-testsuite --test 'js_sdk*' -- --nocapture

.PHONY: www-demo
www-demo: wasm-build-debug
	cp tng-wasm/pkg/tng_wasm.js tng-wasm/www/
	cp tng-wasm/pkg/tng_wasm_bg.wasm tng-wasm/www/
	miniserve ./tng-wasm/www \
		--header "Cross-Origin-Opener-Policy:same-origin" \
		--header "Cross-Origin-Embedder-Policy:require-corp" \
		--port 8083

.PHONY: www-test
www-test:
	node --test tng-wasm/tests/*.test.mjs

.PHONY: wasm-example-serve
wasm-example-serve: wasm-build-debug
	miniserve ./tng-wasm \
		--header "Cross-Origin-Opener-Policy:same-origin" \
		--header "Cross-Origin-Embedder-Policy:require-corp" \
		--port 8082

.PHONY: mac-cross-build
mac-cross-build:
	RUSTFLAGS="-L native=/usr/lib/" cargo zigbuild --target aarch64-apple-darwin

.PHONY: install-windows-build-deps
install-windows-build-deps:
	@if ! command -v zig >/dev/null 2>&1; then \
		echo "=== Installing Zig ==="; \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "aarch64" ]; then ZIG_ARCH="aarch64"; else ZIG_ARCH="x86_64"; fi; \
		ZIG_VERSION=0.16.0; \
		ZIG_DIR=/tmp/zig-$${ZIG_ARCH}-linux-$${ZIG_VERSION}; \
		curl -L "https://zigmirror.com/zig-$${ZIG_ARCH}-linux-$${ZIG_VERSION}.tar.xz" -o /tmp/zig-cross.tar.xz; \
		tar -xJf /tmp/zig-cross.tar.xz -C /tmp/; \
		cp "$$ZIG_DIR/zig" /usr/local/bin/zig; \
		cp -rf "$$ZIG_DIR/lib" /usr/local/lib/; \
		cp -rf "$$ZIG_DIR/doc" /usr/local/doc/ 2>/dev/null || true; \
		cp -f "$$ZIG_DIR/LICENSE" /usr/local/ 2>/dev/null || true; \
		rm -f /tmp/zig-cross.tar.xz; \
		rm -rf "$$ZIG_DIR"; \
	fi
	@if ! command -v x86_64-w64-mingw32-dlltool >/dev/null 2>&1; then \
		echo "=== Installing MinGW-w64 toolchain ==="; \
		yum install -y mingw64-gcc; \
	fi
	@if ! cargo --list 2>/dev/null | grep -q zigbuild; then \
		echo "=== Installing cargo-zigbuild ==="; \
		rustup toolchain add nightly >/dev/null 2>&1; \
		cargo +nightly install cargo-zigbuild --version 0.19.8; \
	fi
	@rustup target list | grep -q "x86_64-pc-windows-gnu (installed)" || rustup target add x86_64-pc-windows-gnu

.PHONY: windows-cross-build
windows-cross-build: install-windows-build-deps
	RUSTFLAGS="--cfg tokio_unstable" cargo zigbuild --target x86_64-pc-windows-gnu --release

.PHONY: clippy
clippy:
	cargo clippy --all-targets -- -D warnings

# Test dependencies: API Server Rest (ASR) + Attestation Agent (blocking)
# Clones the inclavare-containers community version (main branch) which includes
# PR #91 features: /info, encoding parameter, /additional-evidence.
# Both AA and ASR are built from source to ensure compatibility.
.PHONY: test-dep-aa
test-dep-aa:
	@if [ -d /tmp/guest-components ] && [ ! -d /tmp/guest-components/.git ]; then \
		rm -rf /tmp/guest-components; \
		git clone https://github.com/inclavare-containers/guest-components.git --branch main /tmp/guest-components; \
	elif [ ! -d /tmp/guest-components ]; then \
		git clone https://github.com/inclavare-containers/guest-components.git --branch main /tmp/guest-components; \
	else \
		cd /tmp/guest-components && git fetch origin main && git checkout main && git pull; \
	fi; \
	killall ttrpc-aa api-server-rest 2>/dev/null || true; \
	echo "=== Building Attestation Agent ==="; \
	cargo build --release -p attestation-agent --locked --manifest-path /tmp/guest-components/Cargo.toml --bin ttrpc-aa --features "bin ttrpc"; \
	echo "=== Starting Attestation Agent ==="; \
	RUST_LOG=debug /tmp/guest-components/target/release/ttrpc-aa --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock & \
	for i in $$(seq 1 120); do \
		if [ -S /run/confidential-containers/attestation-agent/attestation-agent.sock ]; then \
			echo "Attestation Agent socket ready"; \
			break; \
		fi; \
		echo "Waiting for Attestation Agent..."; \
		sleep 1; \
	done; \
	echo "=== Building API Server Rest ==="; \
	cargo build --release -p api-server-rest --locked --manifest-path /tmp/guest-components/Cargo.toml; \
	mkdir -p /tmp/tng-asr; \
	echo 'bind = "127.0.0.1:8006"' > /tmp/tng-asr/config.toml; \
	echo 'enable_cdh = false' >> /tmp/tng-asr/config.toml; \
	echo 'enable_aa = true' >> /tmp/tng-asr/config.toml; \
	echo 'aa_socket = "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"' >> /tmp/tng-asr/config.toml; \
	RUST_LOG=debug /tmp/guest-components/target/release/api-server-rest --config /tmp/tng-asr/config.toml

# Test dependencies: Attestation Service (with SLSA provenance and Rekor)
# All steps share a single shell block so the backgrounded `crane` process
# stays alive until `restful-as` (the last foreground command) exits — see
# commit 422c112.
.PHONY: test-dep-as
test-dep-as:
	@set -e; \
	echo "=== Starting OCI Registry ==="; \
	if ! command -v crane > /dev/null; then \
		curl -sSL https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz | tar -xzf - -C /usr/local/bin crane; \
		chmod +x /usr/local/bin/crane; \
	fi; \
	killall crane 2>/dev/null || true; \
	crane registry serve --address=:5000 & \
	for i in $$(seq 1 10); do \
		if curl -s http://127.0.0.1:5000/v2/ > /dev/null; then \
			echo "OCI registry is ready"; \
			break; \
		fi; \
		echo "Waiting for OCI registry..."; \
		sleep 1; \
	done; \
	echo "=== Installing SLSA Tools ==="; \
	if ! command -v cosign > /dev/null; then \
		curl -sSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64; \
		chmod +x /usr/local/bin/cosign; \
	fi; \
	if ! command -v rekor-cli > /dev/null; then \
		curl -sSL -o /usr/local/bin/rekor-cli https://github.com/sigstore/rekor/releases/latest/download/rekor-cli-linux-amd64; \
		chmod +x /usr/local/bin/rekor-cli; \
	fi; \
	if ! command -v rv-release-tool > /dev/null; then \
		curl -sSL -o /usr/local/bin/rv-release-tool https://raw.githubusercontent.com/openanolis/trustee/28e0dd301ce1848ae539ee201260d5b85409a3f4/tools/slsa/rv-release-tool; \
		chmod +x /usr/local/bin/rv-release-tool; \
	fi; \
	if ! command -v python3 > /dev/null; then \
		yum install -y python3; \
	fi; \
	echo "=== Generating SLSA Provenance and Uploading to Rekor ==="; \
	mkdir -p /tmp/slsa-test; \
	openssl ecparam -genkey -name prime256v1 -noout -out /tmp/slsa-test.key; \
	echo '#!/bin/bash' > /tmp/slsa-test/demo-app.sh; \
	echo 'echo "Hello, SLSA Provenance Test!"' >> /tmp/slsa-test/demo-app.sh; \
	chmod +x /tmp/slsa-test/demo-app.sh; \
	cd /tmp/ && rv-release-tool \
		--artifact-type binary \
		--artifact /tmp/slsa-test/demo-app.sh \
		--artifact-id test-artifact \
		--artifact-version 1.0.0 \
		--sign-key /tmp/slsa-test.key \
		--rekor-url https://log2025-1.rekor.sigstore.dev \
		--rekor-api-version 2 \
		--provenance-store-protocol oci \
		--provenance-store-uri "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0" \
		--provenance-store-artifact bundle; \
	cd - ; \
	echo "=== Uploading RV Release Manifest Bundle to OCI Registry ==="; \
	cd /tmp/ && rv-release-tool \
		--artifact-type binary \
		--artifact /tmp/slsa-test/demo-app.sh \
		--artifact-id cvm_container_proxy \
		--artifact-version 1.0.0 \
		--sign-key /tmp/slsa-test.key \
		--rekor-url https://log2025-1.rekor.sigstore.dev \
		--rekor-api-version 2 \
		--provenance-store-protocol oci \
		--provenance-store-uri "oci://127.0.0.1:5000/trustee/provenance:cvm_container_proxy-1.0.0" \
		--provenance-store-artifact bundle; \
	cd - ; \
	echo "=== Verifying OCI Registry Upload ==="; \
	curl -s http://127.0.0.1:5000/v2/trustee/provenance/tags/list | jq .; \
	curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
		http://127.0.0.1:5000/v2/trustee/provenance/manifests/test-artifact-1.0.0 | jq .; \
	curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
		http://127.0.0.1:5000/v2/trustee/provenance/manifests/cvm_container_proxy-1.0.0 | jq .;
	echo "=== Starting Attestation Service ==="; \
	if ! command -v restful-as > /dev/null; then \
		systemctl mask trustee || true; \
		yum install -y trustee; \
	fi; \
	systemctl stop trustee || true; \
	killall restful-as 2>/dev/null || true; \
	if ! command -v jq > /dev/null; then yum install -y jq; fi; \
	if ! command -v openssl > /dev/null; then yum install -y openssl; fi; \
	openssl ecparam -genkey -name prime256v1 -out /tmp/as-ca.key; \
	openssl req -x509 -sha256 -nodes -days 365 -key /tmp/as-ca.key -out /tmp/as-ca.pem -subj "/O=Trustee CA" \
		-addext keyUsage=critical,cRLSign,keyCertSign,digitalSignature; \
	openssl ecparam -genkey -name prime256v1 -out /tmp/as.key; \
	openssl req -new -key /tmp/as.key -out /tmp/as.csr -subj "/CN=Trustee/O=Trustee CA"; \
	echo '[v3_req]' > /tmp/as-ext.cnf; \
	echo 'subjectKeyIdentifier = hash' >> /tmp/as-ext.cnf; \
	openssl x509 -req -in /tmp/as.csr -CA /tmp/as-ca.pem -CAkey /tmp/as-ca.key -CAcreateserial \
		-out /tmp/as.pem -days 365 -extensions v3_req -extfile /tmp/as-ext.cnf -sha256; \
	cat /tmp/as.pem /tmp/as-ca.pem > /tmp/as-full.pem; \
	mkdir -p /opt/trustee/attestation-service/policies/opa; \
	echo 'package policy' > /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo '' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default executables := 3' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default hardware := 2' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default configuration := 2' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default file_system := 2' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	cat /etc/trustee/as-config.json | jq '.attestation_token_broker.signer.cert_path="/tmp/as-full.pem" | .attestation_token_broker.signer.key_path="/tmp/as.key" | .rvps_config={"type":"BuiltIn","storage":{"type":"LocalJson"}}' > /tmp/config_with_cert.json; \
	RUST_LOG=debug restful-as --socket 0.0.0.0:8080 --config-file /tmp/config_with_cert.json


# Benchmark: raw TCP vs stunnel vs TNG in isolated ip netns
# Usage: make bench [TNG_BIN=./target/release/tng]
#        make bench-multiplex [TNG_BIN=./target/release/tng]  # tests multiplex=true mode
TNG_BIN ?= ./target/release/tng

.PHONY: bench bench-multiplex
bench:
	@if [ ! -f "$(TNG_BIN)" ]; then \
		echo ">> TNG binary not found at $(TNG_BIN), building release..."; \
		$(MAKE) bin-build; \
	fi
	bash ./scripts/bench.sh

bench-multiplex:
	@if [ ! -f "$(TNG_BIN)" ]; then \
		echo ">> TNG binary not found at $(TNG_BIN), building release..."; \
		$(MAKE) bin-build; \
	fi
	TNG_MULTIPLEX=true bash ./scripts/bench.sh

# Python wheel build for current platform
# Requires: Rust toolchain and hatch (installed automatically if missing)
# Builds tng binary for current platform, embeds it in Python wheel
# Usage: make python-wheel

.PHONY: python-wheel
python-wheel:
	@echo ">> Building tng binary for current platform..."
	cargo build --release -p tng --features 'builtin-as-tdx-rust'
	@echo ">> Copying tng binary to tng-python/bin/scripts/"
	mkdir -p tng-python/bin/scripts
	cp target/release/tng tng-python/bin/scripts/tng
	chmod +x tng-python/bin/scripts/tng
	@echo ">> Building Python wheel..."
	@if ! command -v hatch >/dev/null; then \
		pip install --break-system-packages hatch || pip install hatch; \
	fi
	cd tng-python && hatch build
	@echo ">> Wheel built successfully!"
	@echo ">> Wheel location: tng-python/dist/"
	@ls -lh tng-python/dist/*.whl

# Install the built Python wheel
.PHONY: python-wheel-install
python-wheel-install: python-wheel
	@echo ">> Installing Python wheel..."
	pip install --force-reinstall tng-python/dist/*.whl
	@echo ">> Python wheel installed successfully!"

# Run Python tests
.PHONY: python-test
python-test:
	@echo ">> Running Python unit tests..."
	cd tng-python && python -m pytest tests/test_unit.py -v
	@echo ">> Running Python integration tests (requires TNG binary)..."
	cd tng-python && python -m pytest tests/test_integration.py -v -m e2e


# Go SDK — no CGO, pure Go build
.PHONY: go-build go-test go-test-integration

go-build:
	cd tng-go && go build ./...

go-test:
	cd tng-go && go test -v ./...

go-test-integration:
	cd tng-go && go test -tags=integration -v ./...
