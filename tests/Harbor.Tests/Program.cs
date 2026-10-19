using System.Net.Sockets;
using System.Text;
using Harbor.Core;

int assertions = 0;
void Check(bool condition, string name)
{
    assertions++;
    if (!condition) throw new InvalidOperationException("FAIL: " + name);
}
void Reject(Action action, string name)
{
    try { action(); }
    catch (ArgumentException) { assertions++; return; }
    throw new InvalidOperationException("FAIL: accepted " + name);
}
var adapter = new Adapter("fake", "Controlled test adapter", "192.168.50.2", 24, 7, "192.168.50.1");
var subnet = Scope.Validate("192.168.50.0/24", adapter);
Check(subnet.HostCount == 254 && subnet.Hosts().First() == "192.168.50.1" && subnet.Hosts().Last() == "192.168.50.254", "subnet arithmetic");
Reject(() => Scope.Validate("8.8.8.0/24", adapter), "public range");
Reject(() => Scope.Validate("192.168.51.0/24", adapter), "other subnet");
Reject(() => Scope.Validate("192.168.50.5/24", adapter), "host bits");
Reject(() => Scope.Validate("192.168.0.0/16", adapter), "large scope");
Reject(() => Scope.Validate("127.0.0.1/32", adapter), "loopback");
Reject(() => Scope.Validate("169.254.1.0/24", adapter), "link local");
Reject(() => Scope.Validate("192.168.50.0/0", adapter), "zero prefix");
Reject(() => Scope.Validate("::1/32", adapter), "IPv6");
Reject(() => Scope.Validate("192.168.50.0/24;calc", adapter), "command syntax");
Check(Scope.Validate("192.168.50.2/32", adapter).HostCount == 1, "/32");
Check(Scope.Validate("192.168.50.2/31", adapter).HostCount == 2, "/31");
var wide = adapter with { Address = "10.0.0.2", Prefix = 8 };
Check(Scope.Validate("10.0.0.0/22", wide).HostCount == 1022, "maximum bound");
Check(!Scope.IsPrivate(0xAC200001) && Scope.IsPrivate(0xAC100001) && Scope.IsPrivate(0xAC1F0001), "172 private boundaries");
Check(Kasa.Parse(Kasa.Encode(Encoding.UTF8.GetBytes("""{"system":{"get_sysinfo":{"model":"HS100","alias":"Desk","err_code":0}}}"""))) is { Model: "HS100", Alias: "Desk" }, "Kasa response");
Check(Kasa.Parse(Kasa.Query()) is null, "query is not response");
Check(Kasa.Parse(new byte[9000]) is null, "oversized packet");
foreach (var value in new[] { "[]", "null", "{}", """{"system":[]}""", """{"system":{"get_sysinfo":{"model":42}}}""",
    """{"system":{"get_sysinfo":{"model":"HS100","err_code":-1}}}""", """{"system":{"get_sysinfo":{"model":"HS100","err_code":"0"}}}""", "invalid" })
    Check(Kasa.Parse(Kasa.Encode(Encoding.UTF8.GetBytes(value))) is null, "hostile packet " + value);
var random = new Random(17);
for (int i = 0; i < 200; i++) { var bytes = new byte[random.Next(1, 300)]; random.NextBytes(bytes); Check(Kasa.Parse(bytes) is null, "malformed fuzz"); }
Check(Device.Clean("Hello\n\u202EWorld") == "HelloWorld", "control and bidi stripping");
Check(Device.NormalizeMac("01:23:45:67:89:AB") is null && Device.NormalizeMac("00-11-22-33-44-55") == "00:11:22:33:44:55", "MAC evidence validation");
Check(VendorLookup.Lookup("50:C7:BF:00:00:01") == "TP-Link Technologies (OUI registrant)", "bundled OUI match");
Check(VendorLookup.Lookup("52:C7:BF:00:00:01") == "Unknown", "locally administered MAC must not inherit OUI");
Check(VendorLookup.Lookup("00:11:22:33:44:55") == "Unknown" && VendorLookup.Lookup(null) == "Unknown", "unknown OUI stays unknown");
Check(Export.Cell(" =HYPERLINK(\"x\")").StartsWith("\"'"), "formula defense");
Check(Export.Cell("\t=1").StartsWith("\"'"), "tab formula defense");
Check(Export.Cell("a,\"b\"\r\nc") == "\"a,\"\"b\"\"\r\nc\"", "CSV quoting");
var now = DateTimeOffset.UtcNow;
var cached = new Device("192.168.50.1", "00:11:22:33:44:55", "Unknown", null, null, "Gateway", false, null, now, "cache");
var response = cached with { Mac = null, Responded = true, LastSeen = now, Evidence = "ICMP" };
var merged = Device.Merge(response, cached);
Check(merged.Responded && merged.LastSeen == now && merged.Mac == cached.Mac && merged.Evidence == "ICMP; cache", "cache does not downgrade response");
var snapshot = new ScanExport("192.168.50.0/24", true, true, "canceled", 2, [cached with { Hostname = "=1+1" }]);
var csv = Export.Csv(snapshot);
Check(csv.Split("\r\n")[0].Split(',').Length == 15 && csv.Contains("\"'=1+1\"") && csv.Contains("\"canceled\",\"True\",\"2\""), "CSV shape, context and formula protection");
using (var json = System.Text.Json.JsonDocument.Parse(Export.Json(snapshot)))
    Check(json.RootElement.GetProperty("schemaVersion").GetInt32() == 1 &&
        json.RootElement.GetProperty("demo").GetBoolean() &&
        json.RootElement.GetProperty("partial").GetBoolean() &&
        json.RootElement.GetProperty("status").GetString() == "canceled" &&
        json.RootElement.GetProperty("devices").GetArrayLength() == 1, "JSON output schema and partial context");
var fake = new FakeProbe();
var updates = new InlineProgress();
var scan = new Scanner(fake);
var started = System.Diagnostics.Stopwatch.StartNew();
var rows = await scan.RunAsync(Scope.Validate("192.168.50.0/29", adapter), adapter, new(true, false), updates, CancellationToken.None);
Check(rows.Count == 2 && rows.Single(d => d.Ip.EndsWith(".1")).Responded && !rows.Single(d => d.Ip.EndsWith(".3")).Responded, "dedup and stale classification");
Check(fake.Peak <= 8 && started.ElapsedMilliseconds >= 300, "bounded concurrency and pacing");
Check(updates.Values.Any(u => u.Error is not null), "probe errors surfaced");
var slow = new FakeProbe { Delay = 350 };
var slowUpdates = new InlineProgress();
started.Restart();
await new Scanner(slow).RunAsync(Scope.Validate("192.168.50.0/28", adapter), adapter, new(false, false), slowUpdates, CancellationToken.None);
Check(slow.Peak is > 1 and <= 8 && started.ElapsedMilliseconds >= 840, "pacing and concurrent in-flight work");
Check(slowUpdates.Values.Max(u => u.Completed) == 14, "all finite targets attempted");
var dnsUpdates = new InlineProgress();
var dnsRows = await new Scanner(new FakeProbe { DnsError = true, NeighborError = true }).RunAsync(
    Scope.Validate("192.168.50.1/32", adapter), adapter, new(false, true), dnsUpdates, CancellationToken.None);
Check(dnsRows.Single().Responded, "DNS failure preserves confirmed response");
Check(dnsUpdates.Values.Count(u => u.Error is not null) == 3, "both neighbor snapshots and DNS errors visible");
using var cancel = new CancellationTokenSource();
cancel.CancelAfter(150);
try { await scan.RunAsync(subnet, adapter, new(false, false), updates, cancel.Token); throw new InvalidOperationException("Cancellation ignored"); }
catch (OperationCanceledException) { assertions++; }
Console.WriteLine($"PASS: {assertions} assertions (mock-only; no network calls)");

sealed class InlineProgress : IProgress<ScanUpdate>
{
    public System.Collections.Concurrent.ConcurrentBag<ScanUpdate> Values { get; } = [];
    public void Report(ScanUpdate value) => Values.Add(value);
}
sealed class FakeProbe : INetworkProbe
{
    private int active;
    public int Peak;
    public int Delay { get; init; } = 20;
    public bool DnsError { get; init; }
    public bool NeighborError { get; init; }
    public IReadOnlyList<Neighbor> Neighbors(Adapter adapter) => NeighborError
        ? throw new System.ComponentModel.Win32Exception(5)
        : [new("192.168.50.1", "001122334455"), new("192.168.50.3", "001122334466")];
    public async Task<ProbeResult> ProbeAsync(string ip, Adapter adapter, bool kasa, CancellationToken token)
    {
        int current = Interlocked.Increment(ref active);
        Peak = Math.Max(Peak, current);
        try
        {
            await Task.Delay(Delay, token);
            if (ip.EndsWith(".4")) throw new SocketException((int)SocketError.AccessDenied);
            return new(ip.EndsWith(".1"), 2, null, null, "mock ICMP");
        }
        finally { Interlocked.Decrement(ref active); }
    }
    public Task<string?> ResolveAsync(string ip, CancellationToken token) =>
        DnsError ? throw new TimeoutException("Mock DNS timeout") : Task.FromResult<string?>("mock.local");
}
