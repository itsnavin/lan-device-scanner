using System.Text;
using System.Text.Json;

namespace Harbor.Core;

// Independent wire-format implementation; no python-kasa source is included.
public static class Kasa
{
    public static byte[] Query() => Encode(Encoding.UTF8.GetBytes("{\"system\":{\"get_sysinfo\":{}}}"));
    public static byte[] Encode(ReadOnlySpan<byte> plain)
    {
        byte key = 171;
        var result = new byte[plain.Length];
        for (int i = 0; i < plain.Length; i++) { key ^= plain[i]; result[i] = key; }
        return result;
    }

    public static (string? Model, string? Alias)? Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length is < 2 or > 8192) return null;
        byte key = 171;
        var plain = new byte[packet.Length];
        for (int i = 0; i < packet.Length; i++) { plain[i] = (byte)(packet[i] ^ key); key = packet[i]; }
        try
        {
            using var json = JsonDocument.Parse(plain, new JsonDocumentOptions { MaxDepth = 12 });
            if (json.RootElement.ValueKind != JsonValueKind.Object ||
                !json.RootElement.TryGetProperty("system", out var system) || system.ValueKind != JsonValueKind.Object ||
                !system.TryGetProperty("get_sysinfo", out var info) || info.ValueKind != JsonValueKind.Object)
                return null;
            if (info.TryGetProperty("err_code", out var error) && (error.ValueKind != JsonValueKind.Number || !error.TryGetInt32(out int code) || code != 0))
                return null;
            string? Field(string name)
            {
                if (!info.TryGetProperty(name, out var field) || field.ValueKind != JsonValueKind.String) return null;
                var clean = Device.Clean(field.GetString(), 100);
                return clean.Length == 0 ? null : clean;
            }
            var model = Field("model");
            return model is null ? null : (model, Field("alias"));
        }
        catch (JsonException) { return null; }
    }
}
