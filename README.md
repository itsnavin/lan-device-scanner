# Harbor - Windows local-network explorer

A real **Windows desktop application**, not a website pretending to scan your
network. Harbor pairs a dark/light WPF dashboard with bounded, explicitly
authorized local IPv4 discovery. It shows observations and their evidence,
not a misleading "all devices found" or "offline" verdict.

## Get the desktop app

Requires **Windows 11 x64** (or a Windows version supported by .NET 10).
No administrator privileges, packet capture driver, Python, browser server,
or installed .NET runtime is needed for the self-contained package.

1. Open [Windows desktop builds](https://github.com/itsnavin/lan-device-scanner/actions/workflows/windows.yml).
2. Select a successful run for `main`, then download the **Harbor-win-x64** artifact
   (GitHub may require sign-in to download workflow artifacts; no device credentials are involved).
3. Extract the downloaded artifact, then extract the contained `Harbor-win-x64.zip`
   into a folder. Keep **all** the extracted files together.
4. Run **Harbor.exe**. Use **Load demo** to explore the interface without discovery.

These are **unsigned development builds**, not signed/trusted installer releases.
Windows or your organization may block unfamiliar executables. Do not disable
SmartScreen, antivirus, execution policy, firewall, or enterprise restrictions.
Use your organization's normal approval process or build the source yourself.
Artifacts expire after 30 days; rerun the workflow or build locally if unavailable.

## Use safely

Choose an Ethernet/Wi-Fi adapter and inspect its private IPv4 CIDR. The suggested
scope is the actual subnet when /24 or smaller; larger adapter subnets get an
**explicitly displayed /24 starting suggestion**, not a silently truncated scan.
You can edit it to /22 through /32, with at most **1,022 targets**. The entire
scope must fit inside the selected adapter's actual subnet and one RFC 1918
private range (10/8, 172.16/12, or 192.168/16).

**Authorize and scan** presents the exact adapter, CIDR, host count and enabled
operations. Nothing is probed before you approve that dialog, and approval is
required for every scan. Only scan networks you own or are explicitly authorized
to inspect. VPN, tunnel, loopback and recognizable virtual adapters are excluded.
Custom VPN products can look like Ethernet; verify the selected adapter yourself.
The route to each target must also use the selected interface or the target is
skipped with an operation notice. Avoid changing adapters/routes during a scan.

- **Start / cancel / progress:** one scan at a time, eight workers, a globally
  paced launch every 60 ms (at most about 17 hosts/second), finite timeouts,
  no automatic retries or continuous background scans.
- **Search / filter / sort:** search IP, MAC, vendor, hostname, model or role;
  filter responses, cache-only rows or legacy Kasa claims; click headers to sort
  (IP addresses sort numerically). Select a row for the evidence inspector.
- **Export CSV / JSON:** exports all current observations, not just the filtered
  view, including UTC observation/response timestamps and evidence. Both formats
  record scope, demo/partial state, scan outcome and notice count (CSV repeats
  context per row). In-progress, canceled, failed or notice-bearing scans are
  marked partial. Demo CSV filenames and evidence are also labeled.
  CSV quotes every cell, doubles embedded quotes and prefixes
  spreadsheet formula-like text with an apostrophe. JSON is plain data, not
  spreadsheet-ready; do not import arbitrary JSON text as spreadsheet formulas.
- **Errors:** operation failures are counted and shown in a bounded notice log
  (first 250 messages). Timeouts mean no observed response, not an offline device.
  Partial observations remain visible after cancel or failure.

## What is actually discovered

| Signal | What Harbor does | What it does **not** prove |
| --- | --- | --- |
| ICMP | One bounded echo request per selected target; records response time | No reply is not "offline"; firewalls can block ICMP |
| Neighbor cache | Reads the Windows IPv4 neighbor table for the chosen interface, before and after probes | A cache entry can be stale; its age/last response is unknown |
| MAC | Displays only an actual six-byte Windows neighbor-table address | No fabricated MAC from a protocol response, hostname or IP |
| This PC | Selected adapter's actual Windows physical address and local computer name | Local metadata is separate from remote response evidence |
| OUI | Offline Wireshark registry: over 52,000 assignments, longest-prefix /36, /28, /24 matching | Not exhaustive/current; registrant may be a chipset/bridge supplier, not device brand |
| Reverse DNS | Optional 800 ms cancellable lookup per responding host, off by default; sanitized hostname only | A name is not verified identity; configured DNS resolver may be outside the LAN |
| Legacy Kasa | Optional unicast UDP 9999 XOR-encoded `system.get_sysinfo`, no TCP prefix; validates bounded JSON response | Unauthenticated self-reported model/alias, not cryptographically verified identity |
| Gateway / this PC | Labels addresses matching selected adapter metadata | Roles are local configuration, not product detection |

**TP-Link support:** older Kasa devices that implement UDP 9999 `get_sysinfo`
may report a model and alias, even when ICMP is blocked. Harbor sends only that
read-only query, once per target, if enabled. Newer **Tapo / Kasa SMART / KLAP**
families commonly use UDP 20002 discovery and authenticated protocols; **those
protocols are not implemented here**. They may still appear through ICMP,
neighbor evidence or a known OUI, but their model may remain unknown.
Harbor never requests credentials, logs into devices, sends control/toggle
commands, tries default passwords, bypasses authentication, or probes broad
port ranges. SSDP and mDNS broadcasts are not implemented.

MAC OUI lookup is strictly offline. The embedded **Wireshark 4.0.17 `manuf`**
registry replaces the original five-prefix table. It contains **52,417**
/24, /28 and /36 source entries (the effective count is displayed in the app
after excluding special, multicast and locally administered ranges).
The current effective lookup contains **52,197 assignments**: 36,011 /24,
5,479 /28, and 10,707 /36 entries.
Matching uses the longest assignment, so an MA-S /36 or MA-M /28 registrant
takes precedence over the parent MA-L /24 block owner. Unmatched, multicast,
invalid or locally administered/randomized MACs stay **Unknown**.

This is an established **GPL-2.0-or-later** Wireshark dataset, pinned to
commit `882448bcf104995d64853a11b0d160783668d2fa`, with upstream registry
source dates of **August 25, 2024**; it can miss newer assignments.
The unmodified original file, copyright, source references and GPL text
are retained. See [data/NOTICE.txt](data/NOTICE.txt) for SHA256, provenance,
license and update instructions. No MAC addresses or inventory are sent
to vendor APIs, including during updates.

### Why some devices still have no name

Reachability, address-block registrant, hostname, alias and product model
are different facts. An ICMP reply provides **no hostname or model**. Before
scanning, optionally check **Look up hostnames (reverse DNS, optional)**;
the authorization dialog will show it enabled. This is not silently turned
on by this update. DNS names depend on the router/resolver's PTR records
and may not exist even for a working device.

The **NAME SOURCE / REASON** column and inspector distinguish lookup
disabled, no record, timeout, failure, local computer name and a returned
resolver hostname. A Kasa-reported alias is now used as the device's display
name when no hostname is available; model and service vendor claims have
their own fields instead of being presented as a hostname or OUI result.
Vendor identity is never fabricated from a hostname or model.

SSDP/mDNS and modern TP-Link discovery were evaluated but are **not enabled
or implemented** by this update. They require additional multicast/
broadcast scope handling and hostile-packet/protocol validation; many
devices do not announce a name through them anyway. Rather than secretly
adding traffic or fetching untrusted device description URLs, this release
keeps the authorized ICMP/legacy Kasa/optional DNS paths. No login or
authentication bypass is attempted. Devices without a published DNS name
or supported service alias will truthfully remain **No name available**.

Guest/client isolation, VLANs, routed networks, sleeping devices, firewalls,
Wi-Fi power saving and stale neighbor caches limit visibility. Routed neighbors
may expose only a gateway/bridge MAC. Randomized MACs do not identify a vendor.
IPv6 discovery is not implemented. **Actual vendor/model accuracy and physical
TP-Link hardware discovery have not been validated against real devices.**

## Privacy and security boundaries

There is no analytics, cloud service, persistent device history, automatic
scan, hidden web server, browser script execution, shell-command surface or
remote resource loading in the desktop app. Results live in memory until
you explicitly export them; treat exports as sensitive network inventory.
Reverse DNS, when enabled, uses Windows' configured resolver. Discovery
metadata is untrusted: packet size/depth/type checks, control/bidirectional
format character stripping and length caps precede display. Device strings
are rendered as text, never HTML, executable links or scripts.

The app runs as the current user. If Windows denies a network operation, the
notice is shown rather than changing settings or asking for elevation.
The application does not change firewall rules, interfaces or system policy.
Windows routing can change mid-scan; route checks are not a network security
boundary against an actively reconfigured host. Stop scanning before changing
network configuration.

## Build, test and package

Install the official **.NET 10 SDK** on Windows. There are no third-party NuGet
dependencies. The UI uses WPF and Windows IP Helper APIs; the engine and mock
test harness are separate projects.

```powershell
dotnet run --project tests\Harbor.Tests -c Release
dotnet build src\Harbor.Desktop -c Release
dotnet run --project src\Harbor.Desktop -c Release -- --demo
dotnet publish src\Harbor.Desktop -c Release -r win-x64 --self-contained true -o artifacts\Harbor-win-x64
artifacts\Harbor-win-x64\Harbor.exe --smoke-test
Copy-Item README.md,LICENSE artifacts\Harbor-win-x64\
Copy-Item data\NOTICE.txt artifacts\Harbor-win-x64\OUI-NOTICE.txt
Copy-Item data\COPYING.WIRESHARK artifacts\Harbor-win-x64\
git archive HEAD -o artifacts\Harbor-win-x64\Harbor-source.zip
[System.IO.Compression.ZipFile]::CreateFromDirectory("$pwd\artifacts\Harbor-win-x64", "$pwd\artifacts\Harbor-win-x64.zip")
```

The self-contained x64 ZIP is a folder deployment, not a single executable.
Full application/data/build source is included in every CI-generated binary
ZIP as `Harbor-source.zip`; build packages from a committed, clean source tree.
Do not enable trimming for WPF. An ARM64 build can be generated with
`-r win-arm64` but is not part of the validated x64 build workflow.

`Harbor.exe --demo` uses only synthetic fixture observations and does not even
enumerate adapters. `--smoke-test` opens the real WPF window in demo mode,
checks bindings, search, status filters, inspector and theme switching, then
exits nonzero on failure. It never starts discovery.

The dependency-free console test harness checks CIDR arithmetic, private
boundaries, adapter/subnet containment, scope limits, malformed/hostile Kasa
packets, deterministic parser fuzz cases, OUI unknown/randomized handling,
merge/stale semantics, CSV formula protection/quoting, pacing, concurrency,
cancellation and surfaced probe errors using a fake network probe.
Tests must never perform real LAN discovery in CI or a shared development host.

The Windows workflow runs those tests, publishes the self-contained app,
launches the demo startup smoke test, creates the ZIP and checks key runtime/
application files in the extracted archive before uploading it.

## Implementation and protocol references

`Harbor.Core` owns scope validation, discovery orchestration, evidence merge,
packet parsing, OUI facts and exports. `Harbor.Desktop` owns the WPF dashboard,
authorization dialog and native Windows probe adapter. The UI is keyboard
operable using standard WPF controls, explicit accessibility names for inputs,
readable contrast and a selectable evidence inspector. Light/dark themes are
session-local.

Protocol research references (not linked runtime dependencies):

- [Microsoft: GetIpNetTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getipnettable)
- [Microsoft: GetBestInterface](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterface)
- [Microsoft: Ping.SendPingAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ping.sendpingasync)
- [python-kasa discovery protocol notes](https://python-kasa.readthedocs.io/en/latest/topics.html#discovery)
- [python-kasa license](https://github.com/python-kasa/python-kasa/blob/master/LICENSE):
  **GPL-3.0-or-later**, not MIT. No python-kasa source is copied, bundled or imported;
  Harbor has an independent, narrow wire-format implementation.

Original Harbor code is MIT licensed. The embedded Wireshark registry is
**GPL-2.0-or-later**; the combined desktop distribution is provided under
GPL-2.0-or-later, with the full corresponding application/data/build source
in `Harbor-source.zip`, license text in `COPYING.WIRESHARK`, and provenance
in `OUI-NOTICE.txt`. Original MIT permissions for Harbor code remain in
`LICENSE`. Bundled Microsoft .NET runtime components retain their separate
licenses and notices in published packages.
