package policy

import rego.v1

# General-purpose appraisal for TNG deployments where only the hardware TEE
# platform needs to be recognized. The executables, configuration and
# file_system dimensions are affirming by default, and data.reference is
# intentionally ignored. This avoids the strict measurement requirements of the
# trustee ear_default_policy_cpu.rego template, which target a specific
# confidential-container deployment and fail (status != affirming) when the
# expected reference values are absent.

default executables := 2
default configuration := 2
default file_system := 2

# Hardware defaults to "unrecognized" and is overridden to affirming only when a
# known TEE platform is present. Detection paths mirror the trustee
# ear_default_policy_cpu.rego so platform recognition stays consistent.
default hardware := 97

# TDX: Intel TDX quote signed by the SGX quoting enclave.
hardware := 2 if {
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
}

# Hygon CSV.
hardware := 2 if {
	input.csv.version in ["1", "2"]
}

# TPM.
hardware := 2 if {
	input.tpm
}

# Generic CPU / SYSTEM attester.
hardware := 2 if {
	input.system
}
