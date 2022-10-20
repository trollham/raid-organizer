pub static PUBLIC_KEY: &[u8; 64] =
    b"09e854bc7b972e46af2dac99a2d4186b227752071b85cd2d51be3f926fc9b970";

pub struct SignatureVerifier<V> {
    pub verifier: V,
}

impl<V> SignatureVerifier<V>
where
    V: ed25519::signature::Verifier<ed25519::Signature>,
{
    pub fn verify(&self, msg: &[u8], signature: &ed25519::Signature) -> Result<(), ed25519::Error> {
        self.verifier.verify(msg, signature)
    }
}
