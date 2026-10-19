using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

// Run from the repository root. Only pinned upstream public data is downloaded.
const string revision = "882448bcf104995d64853a11b0d160783668d2fa";
const string source = $"https://raw.githubusercontent.com/wireshark/wireshark/{revision}/manuf";
using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
byte[] bytes = await http.GetByteArrayAsync(source);
const string expectedHash = "930B098D2B219F0BD69F6643A0FBD1DF4A21B82EF3AF9B2E4AE71A663D992A5E";
if (Convert.ToHexString(SHA256.HashData(bytes)) != expectedHash)
    throw new InvalidOperationException("Pinned upstream registry checksum changed; refusing update.");
string text = Encoding.UTF8.GetString(bytes);
if (!text.Contains("SPDX-License-Identifier: GPL-2.0-or-later", StringComparison.Ordinal))
    throw new InvalidOperationException("Expected upstream data license was not found.");
int entries = 0;
var lengths = new Dictionary<int, int>();
foreach (string line in text.Split('\n'))
{
    if (line.StartsWith('#') || string.IsNullOrWhiteSpace(line)) continue;
    var fields = Regex.Split(line.Trim(), @"\s+", RegexOptions.None, TimeSpan.FromSeconds(1));
    string[] prefix = fields[0].Split('/');
    int bits = prefix.Length == 2 ? int.Parse(prefix[1]) : prefix[0].Count(char.IsAsciiHexDigit) * 4;
    if (bits is not (24 or 28 or 36)) continue;
    entries++;
    lengths[bits] = lengths.GetValueOrDefault(bits) + 1;
}
if (entries < 40000 || !lengths.ContainsKey(28) || !lengths.ContainsKey(36))
    throw new InvalidOperationException("Vendor data failed coverage checks; refusing update.");
Directory.CreateDirectory("data");
await File.WriteAllBytesAsync(Path.Combine("data", "manuf"), bytes);
await File.WriteAllBytesAsync(Path.Combine("data", "COPYING.WIRESHARK"),
    await http.GetByteArrayAsync($"https://raw.githubusercontent.com/wireshark/wireshark/{revision}/COPYING"));
Console.WriteLine($"Source: {source}\nSHA256: {Convert.ToHexString(SHA256.HashData(bytes))}");
Console.WriteLine($"24/28/36-bit source entries: {entries}; " + string.Join(", ", lengths.OrderBy(p => p.Key).Select(p => $"/{p.Key}: {p.Value}")));
