.PHONE: help
help:
	@echo "Read README.md first"

.PHONE: install-test-deps
install-test-deps:
	yum install -y iptables iputils gcc bind-utils tar llvm yum-utils curl iptables openssl iproute

.PHONE: run-test
run-test: install-test-deps
	yum-builddep -y ./trusted-network-gateway.spec

	yum install -y ipset
	./tng-testsuite/run-test.sh

.PHONE: run-test-on-bin
run-test-on-bin: install-test-deps
	yum install -y ipset
	cargo test --no-default-features --features on-bin --package tng-testsuite --tests -- --nocapture


.PHONE: run-test-on-podman
run-test-on-podman: install-test-deps
	yum install -y ipset
	cargo test --no-default-features --features on-podman --package tng-testsuite --tests -- --nocapture


VERSION 	:= $(shell grep '^version' ./tng/Cargo.toml | awk -F' = ' '{print $$2}' | tr -d '"')

.PHONE: create-tarball
create-tarball:
	rm -rf /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/ && mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/

	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/
	cargo vendor --locked --manifest-path ./Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/ | tee /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/.cargo/config.toml

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

	rsync -a --exclude target ./ /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src/

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

.PHONE: mac-cross-build
mac-cross-build:
	RUSTFLAGS="-L native=/usr/lib/" cargo zigbuild --target aarch64-apple-darwin
