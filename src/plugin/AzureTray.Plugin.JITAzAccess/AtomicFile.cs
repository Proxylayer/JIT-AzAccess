using System;
using System.IO;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Crash-safe replacement for <see cref="File.WriteAllText(string, string)"/>.
/// </summary>
/// <remarks>
/// <c>File.WriteAllText</c> truncates the target before it writes, so a crash,
/// a power loss or an upgrade that kills the process mid-write leaves a
/// zero-length or half-written file. For the plugin's stores that reads back as
/// "no favorites" / "no rules" — a silent reset the user never asked for and
/// cannot tell from a genuine empty store.
///
/// Writing to a sibling temp file and renaming over the target means a reader
/// only ever sees the complete old content or the complete new content. The
/// rename is same-directory (so same volume), which is where the platform's
/// rename is atomic; a crash before it leaves the old file untouched.
/// </remarks>
internal static class AtomicFile
{
    public static void WriteAllText(string path, string contents)
    {
        var dir = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(dir)) dir = ".";

        // Unique per write so two processes racing on the same store cannot
        // scribble over each other's temp file and produce a torn rename.
        var temp = Path.Combine(dir, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");

        try
        {
            File.WriteAllText(temp, contents);
            File.Move(temp, path, overwrite: true);
        }
        catch
        {
            // Leave no temp files behind on a failed write. The original
            // exception is what the caller needs, so cleanup failures here are
            // deliberately swallowed rather than masking it.
            try { if (File.Exists(temp)) File.Delete(temp); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }

            throw;
        }
    }
}
