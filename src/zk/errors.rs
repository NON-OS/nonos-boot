//! ZK error taxonomy 

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkError {
    ProofTooLarge,
    InputsTooLarge,
    InputsMisaligned,
    ManifestMissing,
    ManifestTooLarge,
    CommitmentMismatch,
    UnknownProgramHash,
    VerifyingKeyEmpty,
    VerifyingKeyDeserialize,
    ProofDeserializeA,
    ProofDeserializeB,
    ProofDeserializeC,
    BackendVerifyFailed,
    BackendUnsupported,
    Internal,
    ProofSizeInvalid,
    InputsCountMismatch,
    SectionTooSmall,
    HeaderTruncated,
    OffsetRange,
    HashOffsets,
}

impl ZkError {
    pub fn as_str(self) -> &'static str {
        use ZkError::*;
        match self {
            ProofTooLarge => "zk: proof too large",
            InputsTooLarge => "zk: inputs too large",
            InputsMisaligned => "zk: inputs not multiple of 32",
            ManifestMissing => "zk: manifest missing for binding",
            ManifestTooLarge => "zk: manifest too large",
            CommitmentMismatch => "zk: commitment mismatch",
            UnknownProgramHash => "zk: unknown program hash (no VK)",
            VerifyingKeyEmpty => "zk: VK empty",
            VerifyingKeyDeserialize => "zk: VK deserialize failed",
            ProofDeserializeA => "zk: A deserialize failed",
            ProofDeserializeB => "zk: B deserialize failed",
            ProofDeserializeC => "zk: C deserialize failed",
            BackendVerifyFailed => "zk: groth16 verify failed",
            BackendUnsupported => "zk: no backend (enable zk-groth16)",
            Internal => "zk: internal error",
            ProofSizeInvalid => "zk: proof size invalid",
            InputsCountMismatch => "zk: public inputs count mismatch",
            SectionTooSmall => "zk: section too small",
            HeaderTruncated => "zk: header truncated",
            OffsetRange => "zk: offset range invalid",
            HashOffsets => "zk: hash offsets out of range",
        }
    }
}
