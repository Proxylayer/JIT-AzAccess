namespace AzureTray.Plugin.JITAzAccess;

// Once-then-quiet gate for a per-poll fetch that can fail identically every
// interval for hours (an unhealthy JIT function app returning 500s or hanging
// repeats every ~2-3 min poll all day — that pattern alone once produced ~70%
// of the host's entire log corpus). The state transitions are what carry
// information; the steady state does not:
//
//   success -> failure   log once at Warning WITH the exception,
//   failing -> failing   log at Debug, one line, no stack,
//   failure -> success   log once at Information ("recovered").
//
// A failure whose condition is already reported elsewhere (knownCondition,
// e.g. a 401/403 that NotifyAuthBlocked already toasts and logs) is quiet
// from the FIRST occurrence but still counts toward the failing streak, so
// recovery is still reported once.
//
// Pattern credit: AzureTray.Plugin.PIM's FetchFailureGate (duplicated here
// because plugins are separate assemblies with no shared utility package).
//
// One instance per fetch source (per function-app URL); in-memory only, not
// thread-safe — each tenant's poll loop is single-flighted by a CAS guard.
internal sealed class FetchFailureGate
{
    internal enum FailureLog
    {
        // First failure after a success (or ever): Warning with the exception.
        WarnWithException,

        // Still failing, or a condition another component already reported:
        // one Debug line, exception type + message inline, no stack.
        DebugOneLine,
    }

    private bool _failing;

    public FailureLog RecordFailure(bool knownCondition)
    {
        var wasFailing = _failing;
        _failing = true;
        return wasFailing || knownCondition
            ? FailureLog.DebugOneLine
            : FailureLog.WarnWithException;
    }

    // True when this success ends a failing streak — the caller should log
    // the recovery once at Information.
    public bool RecordSuccess()
    {
        var recovered = _failing;
        _failing = false;
        return recovered;
    }
}
