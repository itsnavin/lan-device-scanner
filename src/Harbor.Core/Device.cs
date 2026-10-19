using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Harbor.Core;

public sealed record Device(
    string Ip, string? Mac, string Vendor, string? Hostname, string? Model,
    string Role, bool Responded, DateTimeOffset? LastSeen, DateTimeOffset ObservedAt,
    string Evidence, long? Latency = null, string? Alias = null,
    string NameEvidence = "Not queried", string MacEvidence = "Windows neighbor cache",
    string? ServiceVendor = null)
{
    public uint IpNumber => Scope.Number(System.Net.IPAddress.Parse(Ip));
    public string Status => Responded ? "Responded" : Role == "This PC" ? "Local interface (not probed)" : "Cache only - unconfirmed";
    public string DisplayName => Hostname ?? Alias ?? (Role == "Device" ? "No name available" : Role);
    public string NameStatus => Hostname is not null ? NameEvidence : Alias is not null ? "Legacy Kasa alias (self-reported)" : NameEvidence;
    public string Identification => Model ?? "No model reported";
    public string MacDisplay => Mac ?? "Not available";
    public string SeenDisplay => LastSeen?.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture) ?? "Unknown (cache only)";
    public string LatencyDisplay => Latency is null ? "-" : $"{Latency} ms";

    public static string Clean(string? value, int max = 160) =>
        string.IsNullOrWhiteSpace(value) ? "" :
        new string(value.Where(c => !char.IsControl(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format).Take(max).ToArray()).Trim();

    public static string? NormalizeMac(string? value)
    {
        if (value is null) return null;
        var hex = value.Replace(":", "").Replace("-", "");
        if (hex.Length != 12 || !hex.All(Uri.IsHexDigit) || hex.All(c => c == '0')) return null;
        var bytes = Convert.FromHexString(hex);
        if ((bytes[0] & 1) != 0) return null;
        return string.Join(":", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    public static Device Merge(Device old, Device next) => next with
    {
        Mac = next.Mac ?? old.Mac,
        Vendor = next.Mac is null || next.Mac == old.Mac ? (next.Vendor == "Unknown" ? old.Vendor : next.Vendor) : next.Vendor,
        Hostname = next.Hostname ?? old.Hostname,
        Model = next.Model ?? old.Model,
        Responded = old.Responded || next.Responded,
        LastSeen = next.LastSeen ?? old.LastSeen,
        Latency = next.Latency ?? old.Latency,
        Alias = next.Alias ?? old.Alias,
        ServiceVendor = next.ServiceVendor ?? old.ServiceVendor,
        NameEvidence = next.Hostname is not null ||
            old.Hostname is null && (!old.Responded || next.Responded) && next.NameEvidence != "Not queried"
                ? next.NameEvidence : old.NameEvidence,
        MacEvidence = next.Mac is null ? old.MacEvidence : next.MacEvidence,
        Evidence = string.Join("; ", old.Evidence.Split("; ").Concat(next.Evidence.Split("; ")).Distinct())
    };
}

public sealed record ScanExport(string? Scope, bool Demo, bool Partial, string Status, int OperationNoticeCount, IReadOnlyList<Device> Devices)
{
    public int SchemaVersion => 2;
    public DateTimeOffset ExportedUtc { get; init; } = DateTimeOffset.UtcNow;
}

public static class Export
{
    public static string Cell(string? value)
    {
        value ??= "";
        if (value.TrimStart().FirstOrDefault() is '=' or '+' or '-' or '@' || value.StartsWith('\t') || value.StartsWith('\r') || value.StartsWith('\n'))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    public static string Csv(ScanExport snapshot)
    {
        var lines = new List<string> { "IP,MAC,Vendor,Hostname,Model,Role,Status,LastSeenUtc,ObservedUtc,Evidence,Scope,Demo,ScanStatus,Partial,OperationNoticeCount,Alias,NameStatus,MacSource,ServiceVendor" };
        lines.AddRange(snapshot.Devices.Select(d => string.Join(",", new[] { d.Ip, d.Mac, d.Vendor, d.Hostname, d.Model, d.Role, d.Status,
            d.LastSeen?.ToString("O"), d.ObservedAt.ToString("O"), d.Evidence, snapshot.Scope, snapshot.Demo.ToString(),
            snapshot.Status, snapshot.Partial.ToString(), snapshot.OperationNoticeCount.ToString(CultureInfo.InvariantCulture),
            d.Alias, d.NameStatus, d.MacEvidence, d.ServiceVendor }.Select(Cell))));
        return string.Join("\r\n", lines) + "\r\n";
    }

    public static string Json(ScanExport snapshot) =>
        JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
}
