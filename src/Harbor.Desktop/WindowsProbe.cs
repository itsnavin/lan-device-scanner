using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Harbor.Core;

namespace Harbor.Desktop;

internal sealed class WindowsProbe : INetworkProbe
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIpNetTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetBestInterface(uint destination, out uint index);

    public IReadOnlyList<Neighbor> Neighbors(Adapter adapter)
    {
        int size = 0;
        uint status = GetIpNetTable(IntPtr.Zero, ref size, false);
        if (status == 232) return [];
        if (status != 122) throw new Win32Exception((int)status);
        if (size is < 4 or > 16_777_216) throw new InvalidOperationException("Unexpected neighbor table size.");
        IntPtr memory = Marshal.AllocHGlobal(size);
        try
        {
            status = GetIpNetTable(memory, ref size, false);
            if (status != 0) throw new Win32Exception((int)status);
            int count = Marshal.ReadInt32(memory);
            const int rowSize = 24;
            if (count < 0 || count > (size - 4) / rowSize) throw new InvalidOperationException("Invalid neighbor table bounds.");
            var rows = new List<Neighbor>();
            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(memory, 4 + i * rowSize);
                if (Marshal.ReadInt32(row) != adapter.Index || Marshal.ReadInt32(row, 4) != 6 ||
                    Marshal.ReadInt32(row, 20) is not (3 or 4)) continue;
                var mac = new byte[6];
                var ip = new byte[4];
                Marshal.Copy(IntPtr.Add(row, 8), mac, 0, 6);
                Marshal.Copy(IntPtr.Add(row, 16), ip, 0, 4);
                rows.Add(new(new IPAddress(ip).ToString(), Convert.ToHexString(mac)));
            }
            return rows;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    public async Task<ProbeResult> ProbeAsync(string ip, Adapter adapter, bool kasa, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var destination = IPAddress.Parse(ip);
        uint status = GetBestInterface(BitConverter.ToUInt32(destination.GetAddressBytes()), out uint index);
        if (status != 0) throw new InvalidOperationException($"Route lookup failed (Windows {status}).");
        if (index != adapter.Index) throw new InvalidOperationException("Route uses a different interface; target skipped.");
        bool responded = false;
        long? latency = null;
        string evidence = "";
        var notices = new List<string>();
        using (var ping = new Ping())
        {
            try
            {
                var reply = await ping.SendPingAsync(destination, TimeSpan.FromMilliseconds(700),
                    new byte[16], new PingOptions(32, true), token);
                if (reply.Status == IPStatus.Success && reply.Address.Equals(destination))
                {
                    responded = true;
                    latency = reply.RoundtripTime;
                    evidence = "ICMP echo response";
                }
                else if (reply.Status != IPStatus.TimedOut)
                    notices.Add($"ICMP returned {reply.Status}; not classified as offline.");
            }
            catch (PingException ex) { notices.Add($"ICMP failed: {ex.Message}"); }
        }
        string? model = null;
        string? alias = null;
        if (kasa && ip != adapter.Address)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(450);
            try
            {
                using var udp = new UdpClient(new IPEndPoint(IPAddress.Parse(adapter.Address), 0));
                // Windows SDK IP_UNICAST_IF (31) has no managed SocketOptionName member.
                const SocketOptionName ipUnicastInterface = (SocketOptionName)31;
                udp.Client.SetSocketOption(SocketOptionLevel.IP, ipUnicastInterface,
                    IPAddress.HostToNetworkOrder(adapter.Index));
                udp.Connect(new IPEndPoint(destination, 9999));
                await udp.SendAsync(Kasa.Query(), timeout.Token);
                var packet = await udp.ReceiveAsync(timeout.Token);
                var info = Kasa.Parse(packet.Buffer);
                if (info is null) notices.Add("Malformed or unsupported UDP 9999 reply.");
                else
                {
                    model = info.Value.Model;
                    alias = info.Value.Alias;
                    responded = true;
                    evidence = string.Join("; ", new[] { evidence, "Legacy Kasa get_sysinfo response (untrusted self-report)" }.Where(s => s.Length > 0));
                }
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { /* Bounded no-response window. */ }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            { evidence += "; UDP 9999 closed (no legacy Kasa response)"; }
            catch (SocketException ex) { notices.Add($"Legacy Kasa UDP failed: {ex.Message}"); }
        }
        return new(responded, latency, model, alias, evidence, notices);
    }

    public async Task<string?> ResolveAsync(string ip, CancellationToken token)
    {
        var entry = await Dns.GetHostEntryAsync(IPAddress.Parse(ip)).WaitAsync(TimeSpan.FromMilliseconds(600), token);
        var name = Device.Clean(entry.HostName);
        return string.IsNullOrEmpty(name) ? null : name;
    }
}
