.PHONE: help install-test-deps run-test

help:
	@echo "Read README.md first"

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

run-test:
	which iptables || { apt-get update && apt-get install -y iptables && update-alternatives --set iptables /usr/sbin/iptables-nft ; }
	which gcc || { apt-get update && apt-get install -y gcc ; }
	./scripts/run-test.sh
