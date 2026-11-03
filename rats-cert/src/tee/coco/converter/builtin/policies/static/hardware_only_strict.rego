package policy

import rego.v1

# Hardware-only appraisal with stricter TDX requirements. It still ignores
# data.reference, but TDX evidence must be bound to a non-debug TD and include
# an event log. The verifier has already replayed the event log against the
# quote RTMRs before these claims reach policy evaluation.

default executables := 2
default configuration := 2
default file_system := 2

default hardware := 97

hardware := 2 if {
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	tdx_debug_disabled
	tdx_eventlog_present
}

hardware := 2 if {
	input.csv.version in ["1", "2"]
}

hardware := 2 if {
	input.tpm
}

hardware := 2 if {
	input.system
}

# td_attributes is serialized as lowercase hex. The debug bit is bit 0 of the
# first byte, so the low nibble of the first byte must be even.
tdx_debug_disabled if {
	regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes)
}

tdx_eventlog_present if {
	count(input.tdx.uefi_event_logs) > 0
}
