using System.Globalization;

namespace Harbor.Core;

public static class VendorLookup
{
    private static readonly IReadOnlyDictionary<string, string> prefixes = Load();

    private static IReadOnlyDictionary<string, string> Load()
    {
        using var stream = typeof(VendorLookup).Assembly.GetManifestResourceStream("Harbor.Oui")
            ?? throw new InvalidOperationException("Bundled OUI fact table is missing.");
        using var reader = new StreamReader(stream);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.ReadLine() is { } line)
        {
            var fields = line.Split('\t');
            if (fields.Length != 3 || fields[0].Length != 6 || !fields[0].All(Uri.IsHexDigit))
                throw new InvalidOperationException("Bundled OUI fact table is invalid.");
            result.Add(fields[0], fields[1]);
        }
        return result;
    }

    public static string Lookup(string? mac)
    {
        string? normalized = Device.NormalizeMac(mac);
        if (normalized is null || (byte.Parse(normalized[..2], NumberStyles.HexNumber, CultureInfo.InvariantCulture) & 2) != 0)
            return "Unknown";
        string prefix = normalized.Replace(":", "")[..6];
        return prefixes.TryGetValue(prefix, out string? vendor) ? $"{vendor} (OUI registrant)" : "Unknown";
    }
}
