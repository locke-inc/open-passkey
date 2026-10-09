import type { CeremonyFacts } from './types.js';
export function ceremonyFlags(facts: CeremonyFacts, uv: string | undefined, attested: boolean): number {
  if (!facts || ['userPresent', 'userVerified', 'backupEligible', 'backupState'].some(key => typeof (facts as any)[key] !== 'boolean')) throw new Error('Explicit boolean ceremony facts required');
  if (!facts.userPresent) throw new Error('Explicit user presence required');
  if (uv === 'required' && !facts.userVerified) throw new Error('User verification required');
  if (facts.backupState && !facts.backupEligible) throw new Error('Invalid backup state');
  return 1 | (facts.userVerified ? 4 : 0) | (facts.backupEligible ? 8 : 0)
    | (facts.backupState ? 16 : 0) | (attested ? 64 : 0);
}
