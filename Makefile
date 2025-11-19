.PHONE: help
help:
	@echo "Read README.md first"

.PHONE: install-test-deps
install-test-deps:
	yum install -y iptables iputils gcc bind-utils tar llvm yum-utils curl iptables openssl iproute ipset jq

.PHONE: run-test
run-test: install-test-deps
	yum-builddep -y ./trusted-network-gateway.spec

	./tng-testsuite/run-test.sh

.PHONE: run-test-on-bin
run-test-on-bin: install-test-deps
	cargo test --no-default-features --features on-bin --package tng-testsuite --tests -- --nocapture


.PHONE: run-test-on-podman
run-test-on-podman: install-test-deps
	cargo test --no-default-features --features on-podman --package tng-testsuite --tests -- --nocapture


VERSION 	:= $(shell grep '^version' ./Cargo.toml | awk -F' = ' '{print $$2}' | tr -d '"')

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
	cd /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src && git clean -xdf

	# delete all checksum (this is required due to previous patch work)
	sed -i 's/checksum = ".*//g' /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src/Cargo.lock

	# create tarball
	tar -czf /tmp/trusted-network-gateway-${VERSION}.tar.gz -C /tmp/trusted-network-gateway-tarball/ trusted-network-gateway-${VERSION}

	@echo "Tarball generated:" /tmp/trusted-network-gateway-${VERSION}.tar.gz


.PHONE: bin-build
bin-build:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

.PHONE: rpm-build
rpm-build:
	# setup build tree rpmdevtools
	rpmdev-setuptree

	# copy sources
	cp /tmp/trusted-network-gateway-${VERSION}.tar.gz ~/rpmbuild/SOURCES/

	# install build dependencies yum-utils
	yum-builddep -y ./trusted-network-gateway.spec
	
	# build
	rpmbuild -ba ./trusted-network-gateway.spec
	@echo "RPM package is:" ~/rpmbuild/RPMS/*/trusted-network-gateway-*

.PHONE: rpm-build-in-docker
rpm-build-in-docker:
	# copy sources
	mkdir -p ~/rpmbuild/SOURCES/
	cp /tmp/trusted-network-gateway-${VERSION}.tar.gz ~/rpmbuild/SOURCES/

	docker run --rm -v ~/rpmbuild:/root/rpmbuild -v .:/code --workdir=/code registry.openanolis.cn/openanolis/anolisos:8 bash -x -c "sed -i -E 's|https?://mirrors.openanolis.cn/anolis/|https://mirrors.aliyun.com/anolis/|g' /etc/yum.repos.d/*.repo ; yum install -y rpmdevtools yum-utils; rpmdev-setuptree ; yum-builddep -y ./trusted-network-gateway.spec ; rpmbuild -ba ./trusted-network-gateway.spec"

.PHONE: rpm-install
rpm-install: rpm-build
	yum remove trusted-network-gateway -y
	ls -t ~/rpmbuild/RPMS/*/trusted-network-gateway-* | head -n 1 | xargs yum install -y

.PHONE: update-rpm-tree
update-rpm-tree:
	# copy sources
	rm -f ../rpm-tree-tng/trusted-network-gateway-*.tar.gz
	cp /tmp/trusted-network-gateway-${VERSION}.tar.gz ../rpm-tree-tng/
	cp ./trusted-network-gateway.spec ../rpm-tree-tng/

.PHONE: docker-build
docker-build:
	docker build -t tng:${VERSION} .

.PHONE: install-wasm-build-dependencies
install-wasm-build-dependencies:
	if ! command -v wasm-pack >/dev/null; then \
		cargo +nightly-2025-07-07 install wasm-pack ; \
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
	cargo clippy --all-targets --all-features -- -D warnings
