using System.Globalization;
using System.Text.RegularExpressions;

namespace Harbor.Core;

public sealed class VendorRegistry
{
    private readonly Dictionary<(int Bits, ulong Prefix), string> prefixes = [];
    public int Count => prefixes.Count;
    public IReadOnlyDictionary<int, int> Coverage => prefixes.Keys.GroupBy(k => k.Bits).ToDictionary(g => g.Key, g => g.Count());

    public VendorRegistry(TextReader reader)
    {
        while (reader.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            var fields = Regex.Split(line.Trim(), @"\s+", RegexOptions.None, TimeSpan.FromSeconds(1));
            if (fields.Length < 2) throw new InvalidOperationException("Invalid bundled vendor row.");
            var parts = fields[0].Split('/');
            string hex = parts[0].Replace(":", "").Replace("-", "").Replace(".", "");
            if (!hex.All(Uri.IsHexDigit) || hex.Length > 12 || parts.Length > 2)
                throw new InvalidOperationException("Invalid bundled vendor prefix.");
            int bits = parts.Length == 2 ? int.Parse(parts[1], CultureInfo.InvariantCulture) : hex.Length * 4;
            // Special protocol/group ranges and full device-address entries are not vendor assignments.
            if (bits is not (24 or 28 or 36)) continue;
            ulong address = ulong.Parse(hex.PadRight(12, '0'), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (((address >> 40) & 3) != 0) continue;
            string name = Device.Clean(fields.Length > 2 ? string.Join(" ", fields.Skip(2)) : fields[1]);
            if (name.Length == 0) throw new InvalidOperationException("Invalid bundled vendor name.");
            if (!prefixes.TryAdd((bits, address >> (48 - bits)), name))
                throw new InvalidOperationException("Duplicate bundled vendor prefix.");
        }
    }

    public string Lookup(string? mac)
    {
        string? normalized = Device.NormalizeMac(mac);
        if (normalized is null) return "Unknown";
        ulong address = ulong.Parse(normalized.Replace(":", ""), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        if (((address >> 40) & 2) != 0) return "Unknown";
        foreach (int bits in new[] { 36, 28, 24 })
            if (prefixes.TryGetValue((bits, address >> (48 - bits)), out string? vendor))
                return $"{vendor} (OUI registrant, /{bits})";
        return "Unknown";
    }

    public string Explain(string? mac) => Device.NormalizeMac(mac) is not { } normalized
        ? "No actual MAC evidence available; vendor lookup is not possible."
        : (byte.Parse(normalized[..2], NumberStyles.HexNumber, CultureInfo.InvariantCulture) & 2) != 0
            ? "Locally administered/randomized MAC; no vendor is inferred."
            : Lookup(mac) == "Unknown"
                ? "No matching assignment in the bundled registry snapshot; vendor remains unknown."
                : "Offline Wireshark registry, longest matching /36, /28 or /24 assignment; registrant is not a verified device brand/model.";
}

public static class VendorLookup
{
    private static readonly VendorRegistry registry = Load();
    public static int Count => registry.Count;
    public static IReadOnlyDictionary<int, int> Coverage => registry.Coverage;
    public static string Lookup(string? mac) => registry.Lookup(mac);
    public static string Explain(string? mac) => registry.Explain(mac);

    private static VendorRegistry Load()
    {
        using var stream = typeof(VendorLookup).Assembly.GetManifestResourceStream("Harbor.Oui")
            ?? throw new InvalidOperationException("Bundled vendor registry is missing.");
        using var reader = new StreamReader(stream);
        var result = new VendorRegistry(reader);
        if (result.Count < 40000) throw new InvalidOperationException("Bundled vendor registry coverage is incomplete.");
        return result;
    }
}
