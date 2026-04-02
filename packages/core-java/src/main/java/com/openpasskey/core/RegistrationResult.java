package com.openpasskey.core;

/**
 * Result of successful WebAuthn registration verification.
 */
public class RegistrationResult {
    private final byte[] credentialId;
    private final byte[] publicKeyCose;
    private final int signCount;
    private final byte[] rpIdHash;
    private final int flags;
    private final boolean backupEligible;
    private final boolean backupState;
    private final String attestationFormat;

    public RegistrationResult(byte[] credentialId, byte[] publicKeyCose, int signCount,
                              byte[] rpIdHash, int flags, boolean backupEligible,
                              boolean backupState, String attestationFormat) {
        this.credentialId = credentialId;
        this.publicKeyCose = publicKeyCose;
        this.signCount = signCount;
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
        this.attestationFormat = attestationFormat;
    }

    public byte[] getCredentialId() { return credentialId; }
    public byte[] getPublicKeyCose() { return publicKeyCose; }
    public int getSignCount() { return signCount; }
    public byte[] getRpIdHash() { return rpIdHash; }
    public int getFlags() { return flags; }
    public boolean isBackupEligible() { return backupEligible; }
    public boolean isBackupState() { return backupState; }
    public String getAttestationFormat() { return attestationFormat; }
}
