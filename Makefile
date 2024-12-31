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
COMMIT_ID 	:= $(shell git describe --match=NeVeRmAtCh --abbrev=99 --tags --always)
# COMMIT_ID 	:= bf2fdc042b63c2b030ca5995684f563c36e53eb4

.PHONE: create-tarball
create-tarball:
	rm -rf /tmp/tng-tarball/tng-${VERSION}/ && mkdir -p /tmp/tng-tarball/tng-${VERSION}/

	cargo vendor --manifest-path ./Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/tng-tarball/tng-${VERSION}/vendor/
	cargo vendor --manifest-path deps/rats-rs/Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/tng-tarball/tng-${VERSION}/vendor/
	# remove unused files
	find /tmp/tng-tarball/tng-${VERSION}/vendor/windows*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	find /tmp/tng-tarball/tng-${VERSION}/vendor/winapi*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	rm -fr /tmp/tng-tarball/tng-${VERSION}/vendor/windows*/lib/*.a
	rm -fr /tmp/tng-tarball/tng-${VERSION}/vendor/winapi*/lib/*.a
	rm -fr /tmp/tng-tarball/tng-${VERSION}/vendor/winapi*/lib/*.lib
	rm -fr /tmp/tng-tarball/tng-${VERSION}/vendor/windows*/lib/*.lib

	rsync -a --exclude target --exclude .git/modules/deps/tng-envoy ./ /tmp/tng-tarball/tng-${VERSION}/src/
	docker rm -f tng-envoy-copy-bin && docker run -d --rm --name tng-envoy-copy-bin ghcr.io/inclavare-containers/tng:${COMMIT_ID} sleep 1000
	mkdir -p /tmp/tng-tarball/tng-${VERSION}/overlay/usr/local/bin/
	docker cp tng-envoy-copy-bin:/usr/local/bin/envoy-static /tmp/tng-tarball/tng-${VERSION}/overlay/usr/local/bin/envoy-static
	docker rm -f tng-envoy-copy-bin

	tar -czf /tmp/tng-${VERSION}.tar.gz -C /tmp/tng-tarball/ tng-${VERSION}

	@echo "Tarball generated:" /tmp/tng-${VERSION}.tar.gz


.PHONE: rpm-build
rpm-build:
	# setup build tree
	which rpmdev-setuptree || { yum install -y rpmdevtools ; }
	rpmdev-setuptree

	# copy tarball
	# cp /tmp/tng-${VERSION}.tar.gz ~/rpmbuild/SOURCES/

	# install build dependencies
	which yum-builddep || { yum install -y yum-utils ; }
	yum-builddep ./tng.spec
	
	# build 
	rpmbuild -ba ./tng.spec
	@echo "RPM package is:" ~/rpmbuild/RPMS/*/tng-*

.PHONE: rpm-install
rpm-install: rpm-build
	yum remove tng -y
	ls -t ~/rpmbuild/RPMS/*/tng-* | head -n 1 | xargs yum install -y
