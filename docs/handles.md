# Permanent account handles

The core's GetAccount field 9 is the permanent handle. XUACS identity lookup uses
it verbatim; email-derived gamertags remain only for legacy accounts missing it.
Enrollment verifies the name against core, and console-free LinkProfile publishes
the handle as the x360 link public code. Existing XUIDs remain unchanged.

KDC key lookup verifies that the stored profile belongs to an active core account
and agrees with its canonical handle. Stale, deleted or mismatched profiles cannot
supply keys for a reclaimed name. The reviewed alpha migration changes core public
names, not numeric IDs or key material. A console with an old name must recover
its profile again; Store.Profile then updates its gamertag while preserving the
existing offline XUID and XenonKey. No new key/profile is minted just to rename it.

There is no general gamertag-change API: handles are immutable. Core owns format,
reserved words, profanity and the 90-day hold after permanent deletion. A future
user rename contract is intentionally outside the permanent-handle design.
