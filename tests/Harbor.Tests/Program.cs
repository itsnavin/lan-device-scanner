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
var hostileAlias = Kasa.Parse(Kasa.Encode(Encoding.UTF8.GetBytes("""{"system":{"get_sysinfo":{"model":"HS100","alias":"Desk\n\u202ePlug"}}}""")));
Check(hostileAlias?.Alias == "DeskPlug", "hostile service alias sanitized");
Check(Device.NormalizeMac("01:23:45:67:89:AB") is null && Device.NormalizeMac("00-11-22-33-44-55") == "00:11:22:33:44:55", "MAC evidence validation");
Check(VendorLookup.Lookup("50:C7:BF:00:00:01").Contains("TP-LINK", StringComparison.OrdinalIgnoreCase), "bundled TP-Link match");
Check(VendorLookup.Lookup("52:C7:BF:00:00:01") == "Unknown", "locally administered MAC must not inherit OUI");
Check(VendorLookup.Lookup(null) == "Unknown" && VendorLookup.Lookup("FF:FF:FF:FF:FF:FF") == "Unknown", "missing and multicast have no vendor");
Check(VendorLookup.Count > 50000 && VendorLookup.Coverage[28] > 5000 && VendorLookup.Coverage[36] > 10000, "broad registry coverage");
Check(VendorLookup.Lookup("00:1A:11:00:00:01").Contains("Google", StringComparison.Ordinal), "broad Google prefix");
Check(VendorLookup.Lookup("00:55:DA:50:00:01").Contains("Nanoleaf", StringComparison.Ordinal), "real MA-M prefix");
var registry = new VendorRegistry(new StringReader("00:11:22\tBase\tBase vendor\n00:11:22:A0:00:00/28\tMedium\tMedium vendor\n00:11:22:AB:C0:00/36\tSmall\tSmall vendor\n"));
Check(registry.Lookup("00:11:22:AB:C1:23").Contains("Small vendor (OUI registrant, /36)", StringComparison.Ordinal), "longest /36 match");
Check(registry.Lookup("00:11:22:AF:11:22").Contains("Medium vendor (OUI registrant, /28)", StringComparison.Ordinal), "/28 fallback");
Check(registry.Lookup("00:11:22:BB:11:22").Contains("Base vendor (OUI registrant, /24)", StringComparison.Ordinal), "/24 fallback");
Check(registry.Lookup("00:33:44:00:00:01") == "Unknown" && registry.Lookup("02:11:22:AB:C0:00") == "Unknown", "unmatched/randomized stay unknown");
Check(VendorLookup.Explain("02:11:22:AB:C0:00").Contains("randomized", StringComparison.Ordinal), "unknown reason");
Check(adapter.ToString() == adapter.Display && !adapter.ToString().Contains("Adapter {", StringComparison.Ordinal), "human-readable adapter");
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
Check(csv.Split("\r\n")[0].Split(',').Length == 19 && csv.Contains("\"'=1+1\"") && csv.Contains("\"canceled\",\"True\",\"2\""), "CSV shape, context and formula protection");
using (var json = System.Text.Json.JsonDocument.Parse(Export.Json(snapshot)))
    Check(json.RootElement.GetProperty("schemaVersion").GetInt32() == 2 &&
        json.RootElement.GetProperty("demo").GetBoolean() &&
        json.RootElement.GetProperty("partial").GetBoolean() &&
        json.RootElement.GetProperty("status").GetString() == "canceled" &&
        json.RootElement.GetProperty("devices").GetArrayLength() == 1, "JSON output schema and partial context");
var fake = new FakeProbe();
var updates = new InlineProgress();
var scan = new Scanner(fake);
var started = System.Diagnostics.Stopwatch.StartNew();
var rows = await scan.RunAsync(Scope.Validate("192.168.50.0/29", adapter), adapter, new(true, false), updates, CancellationToken.None);
Check(rows.Count == 3 && rows.Single(d => d.Ip.EndsWith(".1")).Responded && !rows.Single(d => d.Ip.EndsWith(".3")).Responded, "dedup and stale classification");
Check(rows.Single(d => d.Ip.EndsWith(".1")).NameStatus.Contains("disabled", StringComparison.Ordinal), "DNS disabled explained");
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
Check(dnsRows.Single().NameStatus == "Reverse DNS timed out", "DNS failure reason retained");
var named = await new Scanner(new FakeProbe { DnsResult = new("fixture.example", "Reverse DNS (unverified resolver result)") }).RunAsync(
    Scope.Validate("192.168.50.1/32", adapter), adapter, new(false, true), new InlineProgress(), CancellationToken.None);
Check(named.Single().DisplayName == "fixture.example" && named.Single().NameStatus.Contains("Reverse DNS", StringComparison.Ordinal), "resolved hostname visible");
var noName = await new Scanner(new FakeProbe { DnsResult = new(null, "No reverse DNS record") }).RunAsync(
    Scope.Validate("192.168.50.1/32", adapter), adapter, new(false, true), new InlineProgress(), CancellationToken.None);
Check(noName.Single().NameStatus == "No reverse DNS record" && noName.Single().Hostname is null, "no PTR distinguished from disabled/error");
var aliasRows = await new Scanner(new FakeProbe { KasaResult = true }).RunAsync(
    Scope.Validate("192.168.50.1/32", adapter), adapter, new(true, false), new InlineProgress(), CancellationToken.None);
Check(aliasRows.Single().DisplayName == "Fixture plug" && aliasRows.Single().Model == "HS100" &&
    aliasRows.Single().ServiceVendor is not null && !aliasRows.Single().Vendor.Contains("self-report", StringComparison.Ordinal), "Kasa alias shown; model/service claim separate from OUI");
var localAdapter = adapter with { Mac = "00:1A:11:00:00:01", LocalHostname = "fixture-pc" };
var localRows = await new Scanner(new FakeProbe()).RunAsync(Scope.Validate("192.168.50.2/32", localAdapter), localAdapter,
    new(false, false), new InlineProgress(), CancellationToken.None);
Check(localRows.Single().Mac == localAdapter.Mac && localRows.Single().DisplayName == "fixture-pc" &&
    localRows.Single().MacEvidence == "Local Windows adapter physical address" && !localRows.Single().Responded, "local MAC/name metadata without fabricated response");
var localMerge = Device.Merge(localRows.Single(), localRows.Single() with { Mac = null, Hostname = null, NameEvidence = "Not queried" });
Check(localMerge.Mac == localAdapter.Mac && localMerge.NameStatus == "Local Windows computer name", "local identity survives response merge");
Check((cached with { Model = "HS100", Alias = "Fixture plug" }).DisplayName == "Fixture plug", "alias not hidden by model");
Check((cached with { Model = "HS100", Role = "Device" }).DisplayName == "No name available", "model is not fabricated hostname");
Check(Device.Merge(cached with { Vendor = "Old registrant" }, cached with { Mac = "02:00:00:00:00:01", Vendor = "Unknown" }).Vendor == "Unknown",
    "changed MAC does not inherit prior vendor");
using var cancel = new CancellationTokenSource();
cancel.CancelAfter(150);
try { await scan.RunAsync(subnet, adapter, new(false, false), updates, cancel.Token); throw new InvalidOperationException("Cancellation ignored"); }
catch (OperationCanceledException) { assertions++; }
Console.WriteLine($"Vendor registry: {VendorLookup.Count} effective assignments; " +
    string.Join(", ", VendorLookup.Coverage.OrderBy(p => p.Key).Select(p => $"/{p.Key}: {p.Value}")));
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
    public bool KasaResult { get; init; }
    public NameLookup DnsResult { get; init; } = new("mock.local", "Reverse DNS (mock)");
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
            return new(ip.EndsWith(".1"), 2, KasaResult ? "HS100" : null, KasaResult ? "Fixture plug" : null, "mock ICMP");
        }
        finally { Interlocked.Decrement(ref active); }
    }
    public Task<NameLookup> ResolveAsync(string ip, CancellationToken token) =>
        DnsError ? throw new TimeoutException("Mock DNS timeout") : Task.FromResult(DnsResult);
}
