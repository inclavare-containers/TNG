#![allow(dead_code)]
use anyhow::Result;
use std::path::PathBuf;

/// Self-signed CA that signs the gateway server cert. The ingress trusts this
/// via `ohttp.tls_ca_certs`.
pub const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDMTCCAhmgAwIBAgIUEsAXd1ToLzGHTGdqammdyAsqJT8wDQYJKoZIhvcNAQEL\n\
BQAwIDEeMBwGA1UEAwwVVE5HIFRlc3QgT0hUVFAgVExTIENBMB4XDTI2MDcxNDAz\n\
MjYxOVoXDTM2MDcxMTAzMjYxOVowIDEeMBwGA1UEAwwVVE5HIFRlc3QgT0hUVFAg\n\
VExTIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmRJ2TgQ18bHT\n\
qMRrSVL7erjDdWcX/3xDQxVfQjKAX6JAdAPMcXgZgkq0BqEGjprb5G2uYzIlt/52\n\
PKaZGoVl3mhY0gHEdyyX+ebRz9CVujNxJ44qXGKbybJemy/YeQee13gw3SVvzzTs\n\
c2FXcW5GkkcryRCmP9GrqS2ryBRxywv0/o/zEPU2h2b/Tp7gA/bePhP5KhVvbrOx\n\
LH6Y26FcH6HsRvAHIvlOxavnKNuxJp+3wZwZqcrEIkyQNuOC7l5iBNcG98jrHxdU\n\
5v7l+lvzSmLeqVmBFyJm4pG6TGhK0hsZV5DlwQWkQzF8gMjsTmc2qUav1QD+wc7i\n\
nWS4//FMwQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB\n\
hjAdBgNVHQ4EFgQUXbBOl4YFai2wa48MfhCT+BbsT1YwHwYDVR0jBBgwFoAUXbBO\n\
l4YFai2wa48MfhCT+BbsT1YwDQYJKoZIhvcNAQELBQADggEBAG5R4bwlheWrZKGY\n\
iPQeFYKwLMSTYKqhB6E5O6IzK1h6mpv8DWSr15Al/KIJDzufsm19G1ILtJmpRUkx\n\
lwD24s/lMuK/ZGnM5rjQl6SGlK6lPowIwoateFEgQ+etUxm6Rytmt3JxAMzLUIqH\n\
xny8Sa0tgH0iTidjTPp/y7FxH5Oy3Q9avNIvPDlzc0uwKg1w16Jmn/WfjmIgFK+Z\n\
WvhTpXETb+WAf2hCxDYOtUy595MhcUKhyV46GseFr+xUMNhLg+dkO7r+BYD5DPXV\n\
W39KadJMXmq0w8WODC8qdcjnbQvAqt0wuB80fdba8E7TGjRIoNZWEbcJv3F+WWIg\n\
XNGNEe0=\n\
-----END CERTIFICATE-----\n";

/// Gateway server cert, signed by CA_CERT_PEM, with SANs
/// IP:192.168.1.1, IP:192.168.1.252, IP:127.0.0.1, DNS:localhost.
pub const SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDbjCCAlagAwIBAgIUFDdi7UCCeQJRPdHD3TtEZk8+ESYwDQYJKoZIhvcNAQEL\n\
BQAwIDEeMBwGA1UEAwwVVE5HIFRlc3QgT0hUVFAgVExTIENBMB4XDTI2MDcxNDAz\n\
MjYxOVoXDTM2MDcxMTAzMjYxOVowITEfMB0GA1UEAwwWdG5nLXRlc3Qtb2h0dHAt\n\
Z2F0ZXdheTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMUHwa4YC8F0\n\
TnjVUiVUTh4+s+NLQHeype4LN+FF5ZkMbNQMc5hMCbEMsNRBYE4BHH8GAqpw7AGX\n\
QgUjDxMzUx3pEzFuKF9k5syDVlf9/eb38c12CANsBcfTV+rE/lHl/BREt+0vDJYI\n\
r8JTLsKf+hQqY5+867TL8AkBdo6OrRXACAR3y1iBuuiG+81nFmB7Z4lDi/Z4DUfR\n\
EAlpl1vdxKaxRmUAtSbpcAi8dXGT5iifvIrnJRO8ZU39fgB7faK2GnUUpm+eKFDr\n\
xeslFwIbroIsUmmyR8vFi7sISMNJKtYwLS3U8DbliArBe2GtydcmAdjBahHvKb8O\n\
8MlQ7p7lavECAwEAAaOBnjCBmzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIF\n\
oDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUHpXANNMmD16HM7/W7j58\n\
UpSMcYowHwYDVR0jBBgwFoAUXbBOl4YFai2wa48MfhCT+BbsT1YwJgYDVR0RBB8w\n\
HYcEwKgBAYcEwKgB/IcEfwAAAYIJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IB\n\
AQAmDIz7EMBy3RpWwxYP+t3ifD6p3kL8BHiCOkd2u5eaoM91UVQj3UQps0cpqO0V\n\
yld19XogVMv5UacTUbYerqSTie36p1k2MWbdDufcs2UNQKyUqo+z0hOSerSiIhuL\n\
8fFSGoPQLH/eC61X6CyFjbH8eRwXRFQlGP/OcZZerG4OdefA0h3oeNbFntk3TLPh\n\
eLzm7NfUo636KkltJRQFMjTD2FWbPs/n1xNecSWSaUnK4Vec9CmsSnVfMOYpyoe5\n\
MDBvL9KrboS3GpKN7eEiimj5+iEh6zvvSEiSZrW4UwE2YQ42m71OuUIcQ2BFBlFI\n\
m1PN0+oGwGtCGQPVtmkRLPBe\n\
-----END CERTIFICATE-----\n";

/// Private key matching SERVER_CERT_PEM (unencrypted PKCS#8).
pub const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFB8GuGAvBdE54\n\
1VIlVE4ePrPjS0B3sqXuCzfhReWZDGzUDHOYTAmxDLDUQWBOARx/BgKqcOwBl0IF\n\
Iw8TM1Md6RMxbihfZObMg1ZX/f3m9/HNdggDbAXH01fqxP5R5fwURLftLwyWCK/C\n\
Uy7Cn/oUKmOfvOu0y/AJAXaOjq0VwAgEd8tYgbrohvvNZxZge2eJQ4v2eA1H0RAJ\n\
aZdb3cSmsUZlALUm6XAIvHVxk+Yon7yK5yUTvGVN/X4Ae32ithp1FKZvnihQ68Xr\n\
JRcCG66CLFJpskfLxYu7CEjDSSrWMC0t1PA25YgKwXthrcnXJgHYwWoR7ym/DvDJ\n\
UO6e5WrxAgMBAAECggEBAImOx8a/HP38MIkmDcroF/3/suG+eQzYmgYeqO3LOefn\n\
h9dnthCfDakhfhdCaXUsS3PXg2bxnaPisYIanvy9uYrJXdAF44PuU0B3dYHLX0ew\n\
1Y2nmSKieUqwn9HVpOUS1zJjY7HhRj09ZVAbeSsCO7t2eMVeRYWdWEFBVz9iFy91\n\
/Y5yIryuL5r0J/Eu5EiHUszek+eFtrBsVpIaJOQQ4mV7baAnRZ15hsNRMspD+jPw\n\
oJopcV/rqFwWv5/cQkSmEfOtFv4QPCGjTcaqNH6jyxckiyl/pJwXW94PBtV6PuGd\n\
BDuOSWUhry9AkGcuBUhRTYzrvsI6m6Pe9j/QvRtK4tECgYEA/QWW/V1WPJQwRriF\n\
u2SJAJvt0a6cLSKC0gucy1/u0vPMfPBMqbRs6sygmZlj5NdMJf9mqpefBqQgFYFA\n\
G+XdLs0beypTW1oB2lnF4T4WVdVbt7WVrvMPUS2u9FclVQlUkqREQgtPNn8rvxOV\n\
KrrJbNqenfQiUzPhO8YY1YkgOzUCgYEAx1lztkJgy6yXGdn88oolfQJxWI69G33G\n\
HYyNh0VB4GFTLn43JJH8Tb/47x9QC5F2kKj/oLgZRcz6hUqIfGpNWuXPKGwFBisu\n\
Eh4hpxrWT4LCWLRad1V4PePZNzavS2cVxTOmmKezdKM2zR6ZA21z2jf24NRNTOXh\n\
r9mAtHg8rE0CgYBW+Jfo6S9eTVW2yXB2dF0/T1nUzF80iHtNNd6kbYpLCrBMddD0\n\
OGeD4eiGQ5p5q6OqH/srQkjQYJQCsFXYARAhKTF8CZVzfiHK6zbAcLX+tQL8x7b2\n\
1ud58OkFZfsYGsfuS/aGeRq2Uco4uMN6V5ArEY6aHrO5w8h04mfg5mykzQKBgF5N\n\
KHm9aMCwgkIOZqPtSdKbBzdXPon0s3Vi+chVsNYN9CV4O2mnTW0SNRYY/+qZAzdn\n\
WpWSwRHN52yKV4pTVwh60cZTYwUKBB859b1w6pRuTLVdi7YLzneogyalTcMjnp7M\n\
0jBAlJnGY7Qgl02Rx04hTz4H8BFCZcKj50h34Gu5AoGBALgGRmcM96wX1gVCSWI8\n\
NtGfozayLcNOHiL1YSYSfAm9UFSHobyUPOjlyuIXGEhN04hUsQKd2Oy+UCvgC6/+\n\
OTV43/3HqttFufj8/bdDFFQ2v8DHHXLsr96bXAxpPepqPtIbReqTLnhyCqsybmJ/\n\
JEQQxVoms/nCE6mTyDNazvHk\n\
-----END PRIVATE KEY-----\n";

/// Write the CA cert PEM to a temp file and return its path. The path is fed
/// to the ingress config's `ohttp.tls_ca_certs`.
pub fn write_ca_to_tempfile() -> Result<PathBuf> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tng-test-ohttp-ca.pem");
    std::fs::write(&path, CA_CERT_PEM)?;
    // Leak the tempdir so the file survives the test (drop would delete it).
    std::mem::forget(dir);
    Ok(path)
}
