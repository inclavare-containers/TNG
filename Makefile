.PHONE: help
help:
	@echo "Read README.md first"

.PHONE: install-test-deps
install-test-deps:
	if ! which attestation-agent ; then \
		git clone https://github.com/confidential-containers/guest-components -b 8e6a45dbb6f9c06b66476d4a32a38ba5410f6bc8 ; \
		cd guest-components/attestation-agent ; \
		make ATTESTER=tdx-attester && make install ATTESTER=tdx-attester ; \
	fi

	if ! which restful-as ; then \
		git clone https://github.com/confidential-containers/trustee -b 8af3ee5ef5401ccc5506a0954ce600c405c351f9 ; \
		cd trustee/attestation-service ; \
		make && make install ; \
	fi

.PHONE: run-test
run-test:
	which iptables || { yum install -y iptables ; }
	which gcc || { yum install -y gcc ; }
	./scripts/run-test.sh

VERSION 	:= $(shell grep '^version' Cargo.toml | awk -F' = ' '{print $$2}' | tr -d '"')
# COMMIT_ID 	:= $(shell git describe --match=NeVeRmAtCh --abbrev=99 --tags --always)
# Reuse the pre-built tng-envoy binary
COMMIT_ID 	:= bf2fdc042b63c2b030ca5995684f563c36e53eb4

.PHONE: create-tarball
create-tarball:
	rm -rf /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/ && mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/

	cargo vendor --manifest-path ./Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/
	cargo vendor --manifest-path deps/rats-rs/Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/
	# remove unused files
	find /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/windows*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	find /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/winapi*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/windows*/lib/*.a
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/winapi*/lib/*.a
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/winapi*/lib/*.lib
	rm -fr /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/vendor/windows*/lib/*.lib

	rsync -a --exclude target --exclude deps/rats-rs/build --exclude .git/modules/deps/tng-envoy ./ /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/src/
	docker rm -f tng-envoy-copy-bin && docker run -d --rm --name tng-envoy-copy-bin ghcr.io/inclavare-containers/tng:${COMMIT_ID} sleep 1000
	mkdir -p /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/overlay/usr/local/bin/
	docker cp tng-envoy-copy-bin:/usr/local/bin/envoy-static /tmp/trusted-network-gateway-tarball/trusted-network-gateway-${VERSION}/overlay/usr/local/bin/envoy-static
	docker rm -f tng-envoy-copy-bin

	tar -czf /tmp/trusted-network-gateway-${VERSION}.tar.gz -C /tmp/trusted-network-gateway-tarball/ trusted-network-gateway-${VERSION}

	@echo "Tarball generated:" /tmp/trusted-network-gateway-${VERSION}.tar.gz


define CARGO_CONFIG
[source.crates-io]
replace-with = "vendored-sources"

[source."git+https://github.com/intel/SGXDataCenterAttestationPrimitives?tag=DCAP_1.20"]
git = "https://github.com/intel/SGXDataCenterAttestationPrimitives"
tag = "DCAP_1.20"
replace-with = "vendored-sources"

[source."git+https://github.com/occlum/occlum?tag=v0.29.7"]
git = "https://github.com/occlum/occlum"
tag = "v0.29.7"
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
endef
export CARGO_CONFIG

.PHONE: rpm-build
rpm-build:
	# setup build tree
	which rpmdev-setuptree || { yum install -y rpmdevtools ; }
	rpmdev-setuptree

	# copy sources
	cp /tmp/trusted-network-gateway-${VERSION}.tar.gz ~/rpmbuild/SOURCES/
	@echo "$$CARGO_CONFIG" > ~/rpmbuild/SOURCES/config

	# install build dependencies
	which yum-builddep || { yum install -y yum-utils ; }
	yum-builddep -y ./trusted-network-gateway.spec
	
	# build
	rpmbuild -ba ./trusted-network-gateway.spec
	@echo "RPM package is:" ~/rpmbuild/RPMS/*/trusted-network-gateway-*

.PHONE: rpm-build-in-docker
rpm-build-in-docker:
	# copy sources
	mkdir -p ~/rpmbuild/SOURCES/
	cp /tmp/trusted-network-gateway-${VERSION}.tar.gz ~/rpmbuild/SOURCES/
	@echo "$$CARGO_CONFIG" > ~/rpmbuild/SOURCES/config

	docker run --rm -v ~/rpmbuild:/root/rpmbuild -v .:/code --workdir=/code registry.openanolis.cn/openanolis/anolisos:8 bash -x -c "yum install -y rpmdevtools yum-utils; rpmdev-setuptree ; yum-builddep -y ./trusted-network-gateway.spec ; rpmbuild -ba ./trusted-network-gateway.spec"

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
	@echo "$$CARGO_CONFIG" > ../rpm-tree-tng/config
