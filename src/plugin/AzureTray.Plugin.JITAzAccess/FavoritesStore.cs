using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace AzureTray.Plugin.JITAzAccess;

/// <summary>
/// Thread-safe per-user store of favorite resource IDs. Persisted to
/// DataDir/favorites.json so the user's choices survive plugin restarts.
/// Written through <see cref="AtomicFile"/> so an interrupted save cannot
/// truncate the file and silently reset the user's favorites.
/// </summary>
internal sealed class FavoritesStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly string  _filePath;
    private readonly object  _lock = new();
    private readonly ILogger? _logger;
    private HashSet<string>  _ids;

    public FavoritesStore(string dataDir, ILogger? logger = null)
    {
        _logger = logger;
        Directory.CreateDirectory(dataDir);
        _filePath = Path.Combine(dataDir, "favorites.json");
        _ids = Load();
    }

    public bool IsFavorite(string id)
    {
        if (string.IsNullOrEmpty(id)) return false;
        lock (_lock) return _ids.Contains(id);
    }

    /// <summary>Toggles favorite state. Returns the new state.</summary>
    public bool Toggle(string id)
    {
        if (string.IsNullOrEmpty(id)) return false;
        lock (_lock)
        {
            bool nowFavorite;
            if (_ids.Contains(id)) { _ids.Remove(id); nowFavorite = false; }
            else                   { _ids.Add(id);    nowFavorite = true;  }
            Save();
            return nowFavorite;
        }
    }

    private HashSet<string> Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var json = File.ReadAllText(_filePath);
            var loaded = JsonSerializer.Deserialize<string[]>(json, JsonOptions);
            return new HashSet<string>(loaded ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex,
                "JIT: could not load favorites at {FilePath}; starting empty.", _filePath);
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(_ids.ToArray(), JsonOptions);
            AtomicFile.WriteAllText(_filePath, json);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex,
                "JIT: could not persist favorites to {FilePath}; in-memory state retained.", _filePath);
        }
    }
}
