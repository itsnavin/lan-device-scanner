using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Harbor.Core;

public sealed record Adapter(string Id, string Name, string Address, int Prefix, int Index, string? Gateway, string? Mac = null, string? LocalHostname = null)
{
    public string Display => $"{Name}  |  {Address}/{Prefix}";
    public override string ToString() => Display;
    public string SuggestedScope => Scope.Network(Address, Math.Max(Prefix, 24)).Cidr;

    public static IReadOnlyList<Adapter> List() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 &&
                !new[] { "vpn", "virtual", "tunnel", "wireguard", "tailscale", "zerotier", "hyper-v", "tap-" }
                    .Any(word => (n.Name + " " + n.Description).Contains(word, StringComparison.OrdinalIgnoreCase)))
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && Scope.IsPrivate(Scope.Number(a.Address)))
                .Select(a => new Adapter(n.Id, n.Name, a.Address.ToString(), a.PrefixLength,
                    n.GetIPProperties().GetIPv4Properties().Index,
                    n.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString(),
                    Device.NormalizeMac(n.GetPhysicalAddress().ToString()), Device.Clean(Environment.MachineName))))
            .ToArray();
}

public sealed record Scope(uint First, int Prefix)
{
    public const int MaxHosts = 1022;
    public uint Mask => uint.MaxValue << (32 - Prefix);
    public uint Last => First | ~Mask;
    public int HostCount => Prefix >= 31 ? (int)(Last - First + 1) : (int)(Last - First - 1);
    public string Cidr => $"{Address(First)}/{Prefix}";
    public bool Contains(uint address) => address >= First && address <= Last;
    public IEnumerable<string> Hosts()
    {
        uint start = Prefix >= 31 ? First : First + 1;
        uint end = Prefix >= 31 ? Last : Last - 1;
        for (uint ip = start; ip <= end; ip++) yield return Address(ip);
    }

    public static uint Number(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("IPv4 is required.");
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static string Address(uint ip) => new IPAddress(new byte[] { (byte)(ip >> 24), (byte)(ip >> 16), (byte)(ip >> 8), (byte)ip }).ToString();
    public static bool IsPrivate(uint ip) =>
        (ip >> 24) == 10 || (ip >> 20) == 0xAC1 || (ip >> 16) == 0xC0A8;

    public static Scope Network(string ip, int prefix)
    {
        if (prefix is < 1 or > 32) throw new ArgumentException("Prefix must be 1-32.");
        return new Scope(Number(ParseAddress(ip)) & (uint.MaxValue << (32 - prefix)), prefix);
    }

    private static IPAddress ParseAddress(string value)
    {
        var parts = value.Split('.');
        if (parts.Length != 4 || parts.Any(p => p.Length == 0 || !p.All(char.IsAsciiDigit) || !byte.TryParse(p, out _)))
            throw new ArgumentException("Use a dotted-decimal IPv4 address.");
        return new IPAddress(parts.Select(byte.Parse).ToArray());
    }

    public static Scope Validate(string cidr, Adapter adapter)
    {
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int prefix) || prefix is < 22 or > 32)
            throw new ArgumentException("Use a private IPv4 CIDR /22 through /32 (at most 1,022 hosts).");
        var scope = Network(parts[0], prefix);
        if (Number(ParseAddress(parts[0])) != scope.First)
            throw new ArgumentException($"Use the canonical network address: {scope.Cidr}.");
        var local = Network(adapter.Address, adapter.Prefix);
        if (!IsPrivate(scope.First) || !IsPrivate(scope.Last) || !local.Contains(scope.First) || !local.Contains(scope.Last))
            throw new ArgumentException("The entire scope must be private and inside the selected adapter's actual subnet.");
        if (scope.HostCount > MaxHosts) throw new ArgumentException("Scope exceeds the host limit.");
        return scope;
    }
}
