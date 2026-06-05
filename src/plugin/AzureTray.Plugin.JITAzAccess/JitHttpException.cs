using System;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Thrown by <see cref="JitClient"/> when a JIT function-app call returns a
/// non-success HTTP status. Carries the status code so callers can branch on
/// 401 (token problem) vs 403 (RBAC role missing) vs everything else.
/// </summary>
internal sealed class JitHttpException : Exception
{
    public int     StatusCode { get; }
    public string  Operation  { get; }
    public string? ServerError { get; }

    public JitHttpException(int statusCode, string operation, string? serverError, string fullMessage)
        : base(fullMessage)
    {
        StatusCode  = statusCode;
        Operation   = operation;
        ServerError = serverError;
    }
}
