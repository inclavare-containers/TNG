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

.PHONE: run-test-on-bin
run-test-on-bin: install-test-deps
	cargo test --no-default-features --features on-bin --package tng-testsuite --tests -- --nocapture


.PHONE: run-test-on-podman
run-test-on-podman: install-test-deps
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
	$(eval RPM_DATE := $(shell date +"%a %b %d %Y"))
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
	@echo "New version: $(2)"
	$(call update-cargo-lock)
	$(call update-buildspec-yml,$(2))
	@echo "Updated APPLICATION/tng/buildspec.yml"
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
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

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

.PHONE: install-wasm-build-dependencies
install-wasm-build-dependencies:
	if ! command -v wasm-pack >/dev/null; then \
		cargo +nightly-2025-07-07 install wasm-pack --locked ; \
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
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --chrome ./tng-wasm -Z build-std=std,panic_abort

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

.PHONE: www-demo
www-demo:
	cd tng-wasm/www && npm run start

.PHONE: mac-cross-build
mac-cross-build:
	RUSTFLAGS="-L native=/usr/lib/" cargo zigbuild --target aarch64-apple-darwin

.PHONE: clippy
clippy:
	cargo clippy --all-targets -- -D warnings

# Test dependencies: Attestation Agent + trustiflux-api-server (RESTful bridge)
.PHONY: test-dep-aa
test-dep-aa:
	@echo "=== Installing dependencies ==="
	@if ! command -v attestation-agent > /dev/null; then \
		yum install -y attestation-agent; \
	fi
	@if ! command -v trustiflux-api-server > /dev/null; then \
		yum install -y trustiflux-api-server; \
	fi
	@echo "=== Starting Attestation Agent (background) ==="
	@mkdir -p /run/confidential-containers/attestation-agent
	@pkill -x attestation-agent 2>/dev/null || true
	RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock &
	@echo "Waiting for Attestation Agent socket..."
	@for i in $$(seq 1 30); do \
		if [ -S /run/confidential-containers/attestation-agent/attestation-agent.sock ]; then \
			echo "Attestation Agent is ready"; \
			break; \
		fi; \
		sleep 1; \
	done
	@echo "=== Starting trustiflux-api-server (port 8006) ==="
	@pkill -x trustiflux-api-server 2>/dev/null || true
	trustiflux-api-server --config /etc/trustiflux/trustiflux-api-server.toml

# Test dependencies: Attestation Service (with SLSA provenance and Rekor)
.PHONY: test-dep-as
test-dep-as:
	@set -e; \
	echo "=== Starting OCI Registry ==="; \
	if ! command -v crane > /dev/null; then \
		curl -sSL https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz | tar -xzf - -C /usr/local/bin crane; \
		chmod +x /usr/local/bin/crane; \
	fi; \
	pkill -x crane 2>/dev/null || true; \
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
	if ! command -v slsa-generator > /dev/null; then \
		curl -sSL -o /usr/local/bin/slsa-generator https://github.com/openanolis/trustee/raw/refs/heads/main/tools/slsa/slsa-generator; \
		chmod +x /usr/local/bin/slsa-generator; \
	fi; \
	echo "=== Generating SLSA Provenance and Uploading to Rekor ==="; \
	mkdir -p /tmp/slsa-test; \
	echo "Working directory: /tmp/slsa-test"; \
	cd /tmp/slsa-test && \
		echo '#!/bin/bash' > demo-app.sh && \
		echo 'echo "Hello, SLSA Provenance Test!"' >> demo-app.sh && \
		echo 'echo "This is a test binary for reference value generation"' >> demo-app.sh && \
		echo 'echo "Timestamp: $$(date)"' >> demo-app.sh && \
		echo 'exit 0' >> demo-app.sh && \
		chmod +x demo-app.sh && \
		echo "Artifact SHA256: $$(sha256sum demo-app.sh | awk '{print $$1}')" && \
		export COSIGN_PASSWORD="" && \
		rm -f slsa-test.key slsa-test.pub && \
		cosign generate-key-pair --output-key-prefix slsa-test && \
		/usr/local/bin/slsa-generator \
			--artifact-type binary \
			--artifact ./demo-app.sh \
			--artifact-id test-artifact \
			--artifact-version 1.0.0 \
			--sign-key ./slsa-test.key \
			--rekor-url https://log2025-1.rekor.sigstore.dev \
			--rekor-api-version 2 \
			--provenance-store-protocol oci \
			--provenance-store-uri oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0 \
			--provenance-store-artifact bundle; \
	echo "=== Verifying OCI Registry Upload ==="; \
	curl -s http://127.0.0.1:5000/v2/trustee/provenance/tags/list | jq .; \
	curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
		http://127.0.0.1:5000/v2/trustee/provenance/manifests/test-artifact-1.0.0 | jq .; \
	echo "=== Starting Attestation Service ==="; \
	if ! command -v restful-as > /dev/null; then \
		systemctl mask trustee || true; \
		yum install -y trustee; \
	fi; \
	systemctl stop trustee || true; \
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
	cat /etc/trustee/as-config.json | jq '.attestation_token_broker.signer.cert_path="/tmp/as-full.pem" | .attestation_token_broker.signer.key_path="/tmp/as.key" | .rvps_config={"type":"BuiltIn","storage":{"type":"LocalFs"}}' > /tmp/config_with_cert.json; \
	RUST_LOG=debug restful-as --socket 0.0.0.0:8080 --config-file /tmp/config_with_cert.json
