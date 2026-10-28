using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AzureTray.Plugin.JITAzAccess.Models;

/// <summary>
/// Reads a JSON date-time as an unambiguous UTC <see cref="DateTime"/>.
/// </summary>
/// <remarks>
/// The function app emits expiry timestamps in UTC, but not every path stamps
/// the trailing <c>Z</c>. System.Text.Json hands an offset-less string back as
/// <see cref="DateTimeKind.Unspecified"/>, and every comparison in the plugin
/// is against <see cref="DateTime.UtcNow"/> — so on a machine east of UTC an
/// expiry reads as further away than it is, and west of UTC a live grant can
/// render as already expired. Both are wrong about whether the user currently
/// has access, which is the one thing these timestamps are for.
///
/// An offset-less value is therefore taken at face value as UTC (what the
/// server meant), and a value that carried an offset is converted rather than
/// relabelled.
/// </remarks>
internal sealed class UtcDateTimeConverter : JsonConverter<DateTime>
{
    public override DateTime Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetDateTime();
        return value.Kind switch
        {
            DateTimeKind.Utc   => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _                  => DateTime.SpecifyKind(value, DateTimeKind.Utc),
        };
    }

    public override void Write(
        Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(value, DateTimeKind.Utc)
            : value.ToUniversalTime());
}
