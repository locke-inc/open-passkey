package com.openpasskey.core;

/**
 * Result of successful WebAuthn authentication verification.
 */
public class AuthenticationResult {
    private final int signCount;
    private final int flags;
    private final boolean backupEligible;
    private final boolean backupState;

    public AuthenticationResult(int signCount, int flags, boolean backupEligible, boolean backupState) {
        this.signCount = signCount;
        this.flags = flags;
        this.backupEligible = backupEligible;
        this.backupState = backupState;
    }

    public int getSignCount() { return signCount; }
    public int getFlags() { return flags; }
    public boolean isBackupEligible() { return backupEligible; }
    public boolean isBackupState() { return backupState; }
}
