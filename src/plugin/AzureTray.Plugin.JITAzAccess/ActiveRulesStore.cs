using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AzureTray.Plugin.JITAzAccess.Models;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Thread-safe store for locally-tracked JIT grants.
/// Persists to DataDir/active-rules.json; expired entries are pruned on load
/// so the file stays tidy across restarts.
/// </summary>
internal sealed class ActiveRulesStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly string _filePath;
    private readonly object _lock = new();
    private readonly ILogger? _logger;
    private List<ActiveRule> _rules;

    public ActiveRulesStore(string dataDir, ILogger? logger = null)
    {
        _logger = logger;
        Directory.CreateDirectory(dataDir);
        _filePath = Path.Combine(dataDir, "active-rules.json");
        _rules = Load();
    }

    /// <summary>Returns rules that have not yet expired. Does not write to disk.</summary>
    public IReadOnlyList<ActiveRule> GetActive()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            return _rules.Where(r => r.ExpiryUtc > now).ToList();
        }
    }

    /// <summary>Adds a rule (replacing any existing entry with the same RuleId) and persists.</summary>
    public void Add(ActiveRule rule)
    {
        lock (_lock)
        {
            _rules.RemoveAll(r => r.RuleId == rule.RuleId);
            _rules.Add(rule);
            Save(_rules);
        }
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private List<ActiveRule> Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return new List<ActiveRule>();

            var json   = File.ReadAllText(_filePath);
            var loaded = JsonSerializer.Deserialize<List<ActiveRule>>(json, JsonOptions);
            var now    = DateTime.UtcNow;

            // Drop expired entries on load to keep the file size bounded.
            return loaded?.Where(r => r.ExpiryUtc > now).ToList()
                   ?? new List<ActiveRule>();
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex,
                "JIT: could not load local rule store at {FilePath}; starting with an empty store.",
                _filePath);
            return new List<ActiveRule>();
        }
    }

    private void Save(List<ActiveRule> rules)
    {
        try
        {
            File.WriteAllText(_filePath, JsonSerializer.Serialize(rules, JsonOptions));
        }
        catch (Exception ex)
        {
            // Non-critical: in-memory state is authoritative for the current session.
            _logger?.LogWarning(ex,
                "JIT: could not persist local rule store to {FilePath}; in-memory state retained.",
                _filePath);
        }
    }
}
