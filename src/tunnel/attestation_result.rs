use rats_cert::tee::claims::Claims;

#[derive(Debug, Clone)]
pub struct AttestationResult {
    #[allow(unused)]
    claims: PrettyPrintClaims,
}

impl AttestationResult {
    pub fn from_claims(claims: &Claims) -> Self {
        Self {
            claims: PrettyPrintClaims::new(claims.clone()),
        }
    }
}

#[derive(Clone)]
pub struct PrettyPrintClaims(Claims);

impl PrettyPrintClaims {
    pub fn new(claims: Claims) -> Self {
        Self(claims)
    }
}

impl std::fmt::Debug for PrettyPrintClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_map = f.debug_map();
        self.0.iter().for_each(|(name, value)| {
            match std::str::from_utf8(value.as_ref()) {
                Ok(s) if !s.contains('\0') => debug_map.entry(name, &s),
                _ => debug_map.entry(name, &hex::encode(value)),
            };
        });
        debug_map.finish()
    }
}
