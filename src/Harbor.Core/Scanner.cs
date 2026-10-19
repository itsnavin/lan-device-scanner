using System.Collections.Concurrent;

namespace Harbor.Core;

public sealed record ProbeResult(bool Responded, long? Latency, string? Model, string? Alias, string Evidence, IReadOnlyList<string>? Notices = null);
public sealed record Neighbor(string Ip, string Mac);
public sealed record ScanOptions(bool Kasa, bool ReverseDns);
public sealed record ScanUpdate(int Completed, int Total, Device? Device, string? Error);
public sealed record NameLookup(string? Hostname, string Status, string? Error = null);

public interface INetworkProbe
{
    Task<ProbeResult> ProbeAsync(string ip, Adapter adapter, bool kasa, CancellationToken token);
    IReadOnlyList<Neighbor> Neighbors(Adapter adapter);
    Task<NameLookup> ResolveAsync(string ip, CancellationToken token);
}

public sealed class Scanner(INetworkProbe probe)
{
    public async Task<IReadOnlyList<Device>> RunAsync(Scope scope, Adapter adapter, ScanOptions options,
        IProgress<ScanUpdate> progress, CancellationToken token)
    {
        // Revalidate even callers that constructed Scope directly.
        Scope.Validate(scope.Cidr, adapter);
        var devices = new ConcurrentDictionary<string, Device>();
        int completed = 0;
        string Role(string ip) => ip == adapter.Address ? "This PC" : ip == adapter.Gateway ? "Gateway" : "Device";
        if (scope.Contains(Scope.Number(System.Net.IPAddress.Parse(adapter.Address))))
        {
            var local = new Device(adapter.Address, adapter.Mac, VendorLookup.Lookup(adapter.Mac),
                string.IsNullOrWhiteSpace(adapter.LocalHostname) ? null : Device.Clean(adapter.LocalHostname), null,
                "This PC", false, null, DateTimeOffset.UtcNow, "Local Windows interface metadata (not remote discovery)",
                NameEvidence: "Local Windows computer name", MacEvidence: "Local Windows adapter physical address");
            devices[adapter.Address] = local;
            progress.Report(new(0, scope.HostCount, local, null));
        }
        void Neighbors()
        {
            try
            {
                foreach (var row in probe.Neighbors(adapter))
                {
                    if (!scope.Contains(Scope.Number(System.Net.IPAddress.Parse(row.Ip)))) continue;
                    if (row.Ip == adapter.Address) continue;
                    var mac = Device.NormalizeMac(row.Mac);
                    if (mac is null) continue;
                    string vendor = VendorLookup.Lookup(mac);
                    var d = new Device(row.Ip, mac, vendor, null, null, Role(row.Ip), false, null,
                        DateTimeOffset.UtcNow, "Windows neighbor cache (age unknown; not proof of response)" +
                            (vendor == "Unknown" ? "" : "; Offline Wireshark OUI registry (registrant only)"),
                        NameEvidence: options.ReverseDns ? "Not queried: cache observation has no confirmed response" : "Not queried: reverse DNS disabled");
                    var merged = devices.AddOrUpdate(row.Ip, d, (_, old) => Device.Merge(old, d));
                    progress.Report(new(completed, scope.HostCount, merged, null));
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                progress.Report(new(completed, scope.HostCount, null, $"Neighbor table unavailable: {ex.Message}"));
            }
        }
        Neighbors();
        await Parallel.ForEachAsync(scope.Hosts(), new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = token },
            async (ip, ct) =>
            {
                // Single shared lock keeps launch rate <= ~17 hosts/s, independent of response speed.
                await launchGate.WaitAsync(ct);
                try { await Task.Delay(60, ct); }
                finally { launchGate.Release(); }
                try
                {
                    var result = await probe.ProbeAsync(ip, adapter, options.Kasa, ct);
                    foreach (string notice in result.Notices ?? [])
                        progress.Report(new(Volatile.Read(ref completed), scope.HostCount, null, $"{ip}: {notice}"));
                    if (result.Responded)
                    {
                        string? hostname = null;
                        string nameStatus = options.ReverseDns ? "No hostname returned" : "Not queried: reverse DNS disabled";
                        if (ip == adapter.Address)
                        {
                            hostname = adapter.LocalHostname;
                            nameStatus = "Local Windows computer name";
                        }
                        else if (options.ReverseDns)
                        {
                            try
                            {
                                var lookup = await probe.ResolveAsync(ip, ct);
                                hostname = string.IsNullOrWhiteSpace(lookup.Hostname) ? null : Device.Clean(lookup.Hostname);
                                nameStatus = lookup.Status;
                                if (lookup.Error is not null)
                                    progress.Report(new(completed, scope.HostCount, null, $"{ip}: reverse DNS: {lookup.Error}"));
                            }
                            catch (Exception ex) when (ex is System.Net.Sockets.SocketException or TimeoutException)
                            {
                                nameStatus = ex is TimeoutException ? "Reverse DNS timed out" : "Reverse DNS failed";
                                progress.Report(new(completed, scope.HostCount, null, $"{ip}: reverse DNS: {ex.Message}"));
                            }
                        }
                        var now = DateTimeOffset.UtcNow;
                        var d = new Device(ip, null, "Unknown",
                            hostname, result.Model, Role(ip), true, now, now,
                            result.Evidence + (result.Alias is null ? "" : "; Device alias from legacy Kasa get_sysinfo"), result.Latency,
                            Alias: string.IsNullOrWhiteSpace(result.Alias) ? null : Device.Clean(result.Alias),
                            NameEvidence: nameStatus, ServiceVendor: result.Model is null ? null : "TP-Link (legacy Kasa self-report, unauthenticated)");
                        var merged = devices.AddOrUpdate(ip, d, (_, old) => Device.Merge(old, d));
                        progress.Report(new(Volatile.Read(ref completed), scope.HostCount, merged, null));
                    }
                }
                catch (Exception ex) when (ex is System.Net.NetworkInformation.PingException or System.Net.Sockets.SocketException or InvalidOperationException)
                { progress.Report(new(Volatile.Read(ref completed), scope.HostCount, null, $"{ip}: {ex.Message}")); }
                progress.Report(new(Interlocked.Increment(ref completed), scope.HostCount, null, null));
            });
        Neighbors();
        return devices.Values.OrderBy(d => d.IpNumber).ToArray();
    }

    private readonly SemaphoreSlim launchGate = new(1, 1);
}
