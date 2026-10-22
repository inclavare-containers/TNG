package policy

# Test policy for the upstream (mainline) restful AS: mark every AR4SI trust
# claim as affirming (tier 2) so the e2e CoCo unit tests' verifier, which
# gates on ear.status == affirming, accepts the appraisal. The AS appends the
# TEE class to the requested policy id ("default_cpu" etc.) and evaluates
# that policy, so this file is installed under each default_* id.
#
# "platform" is deliberately absent: the ear crate version used by the AS
# only knows the eight claims listed here, and an unknown claim name panics
# the AS worker during appraisal.

default trust_claims = {
    "instance-identity": 2,
    "configuration": 2,
    "executables": 2,
    "file-system": 2,
    "hardware": 2,
    "runtime-opaque": 2,
    "storage-opaque": 2,
    "sourced-data": 2,
}
