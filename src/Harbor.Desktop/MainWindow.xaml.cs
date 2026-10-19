using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Harbor.Core;
using Microsoft.Win32;

namespace Harbor.Desktop;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<Device> devices = [];
    private readonly ICollectionView view;
    private CancellationTokenSource? cancellation;
    private bool demo;
    private bool light;
    private int errors;
    private string? resultScope;
    private bool partialResults;
    private string resultStatus = "not-scanned";

    public MainWindow(bool demoMode)
    {
        InitializeComponent();
        view = CollectionViewSource.GetDefaultView(devices);
        view.Filter = Matches;
        view.SortDescriptions.Add(new(nameof(Device.IpNumber), ListSortDirection.Ascending));
        DevicesGrid.ItemsSource = view;
        Closing += OnClosing;
        if (demoMode) LoadDemo();
        else RefreshAdapters();
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (cancellation is not null)
        {
            e.Cancel = true;
            cancellation.Cancel();
            StatusText.Text = "Canceling scan. Close again after it stops.";
        }
    }

    private void RefreshAdapters()
    {
        try
        {
            demo = false;
            Adapters.Tag = "Select a private Ethernet or Wi-Fi adapter";
            Adapters.ItemsSource = Adapter.List();
            Adapters.SelectedIndex = 0;
            StatusText.Text = "Ready. Select a private network and authorize the exact scope.";
            if (Adapters.SelectedItem is null) StatusText.Text = "No eligible private Ethernet/Wi-Fi adapter. VPN/virtual adapters are excluded; no scan is available.";
        }
        catch (System.Net.NetworkInformation.NetworkInformationException ex) { Notice($"Adapter enumeration failed: {ex.Message}"); }
    }

    private void Adapter_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (Adapters.SelectedItem is not Adapter adapter || Cidr is null) return;
        Cidr.Text = adapter.SuggestedScope;
        ScopeHint.Text = adapter.Prefix < 24
            ? $"Adapter subnet is /{adapter.Prefix}. The suggested /24 is a smaller, explicit starting scope; edit it if needed (limit /22)."
            : $"Scope suggestion uses this adapter's /{adapter.Prefix} subnet.";
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (demo)
        {
            MessageBox.Show(this, "Demo cannot scan. Use Refresh adapters to return to real mode.", "Demo mode", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (Adapters.SelectedItem is not Adapter chosen) { Notice("Select an eligible adapter first."); return; }
        Scope scope;
        Adapter adapter;
        try
        {
            adapter = Adapter.List().FirstOrDefault(a => a.Id == chosen.Id && a.Address == chosen.Address && a.Index == chosen.Index && a.Prefix == chosen.Prefix)
                ?? throw new ArgumentException("The selected adapter changed. Refresh adapters and select it again.");
            scope = Scope.Validate(Cidr.Text, adapter);
        }
        catch (Exception ex) when (ex is ArgumentException or System.Net.NetworkInformation.NetworkInformationException)
        { Notice(ex.Message); return; }
        var options = new ScanOptions(KasaOption.IsChecked == true, DnsOption.IsChecked == true);
        if (MessageBox.Show(this,
                $"I own or am authorized to scan this local network:\n\n{scope.Cidr}  ({scope.HostCount} IPv4 targets)\n{adapter.Display}\n\n" +
                $"ICMP echo + Windows neighbor cache\nLegacy Kasa read-only UDP 9999: {(options.Kasa ? "ON" : "OFF")}\nReverse DNS: {(options.ReverseDns ? "ON (uses configured DNS resolver)" : "OFF")}\n\n" +
                "No response does not mean offline. No device login or control commands are sent.\n\nAuthorize and begin this scan?",
                "Confirm authorized local scope", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        devices.Clear();
        Counts();
        ScanProgress.Value = 0;
        DetailTitle.Text = "Select an observation";
        DetailBody.Text = "Scanning. Select a result to inspect its evidence.";
        resultScope = scope.Cidr;
        partialResults = true;
        resultStatus = "scanning";
        errors = 0;
        Errors.Clear();
        ErrorPanel.Header = "Operation notices (0)";
        cancellation = new();
        SetBusy(true);
        var progress = new Progress<ScanUpdate>(update =>
        {
            if (update.Device is { } device)
            {
                var old = devices.FirstOrDefault(d => d.Ip == device.Ip);
                if (old is null) devices.Add(device);
                else devices[devices.IndexOf(old)] = device;
                Counts();
            }
            if (update.Error is not null) Notice(update.Error);
            ScanProgress.Value = update.Completed * 100d / update.Total;
            StatusText.Text = $"Scanning {scope.Cidr}  |  {update.Completed} / {update.Total} checked  |  {devices.Count} observations";
        });
        try
        {
            await new Scanner(new WindowsProbe()).RunAsync(scope, adapter, options, progress, cancellation.Token);
            partialResults = errors > 0;
            resultStatus = errors > 0 ? "completed-with-notices" : "completed";
            StatusText.Text = $"Finished {scope.Cidr}. {devices.Count} observations; {errors} notices. This is not an exhaustive inventory.";
            ScanProgress.Value = 100;
        }
        catch (OperationCanceledException) { resultStatus = "canceled"; StatusText.Text = $"Canceled. {devices.Count} partial observations retained; {errors} notices."; }
        catch (Exception ex) when (ex is InvalidOperationException or System.Net.NetworkInformation.NetworkInformationException)
        { resultStatus = "failed"; Notice($"Scan stopped: {ex.Message}"); StatusText.Text = "Scan failed; partial observations retained. See operation notices."; }
        finally
        {
            cancellation.Dispose();
            cancellation = null;
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        ScanButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        RefreshButton.IsEnabled = !busy;
        DemoButton.IsEnabled = !busy;
        Adapters.IsEnabled = !busy;
        Cidr.IsEnabled = !busy;
        KasaOption.IsEnabled = !busy;
        DnsOption.IsEnabled = !busy;
    }

    private void Notice(string message)
    {
        errors++;
        // Retain a bounded log while preserving the total failure count.
        if (errors <= 250) Errors.AppendText(Device.Clean(message, 500) + Environment.NewLine);
        else if (errors == 251) Errors.AppendText("Further notices omitted from this bounded display; total count continues." + Environment.NewLine);
        ErrorPanel.Header = $"Operation notices ({errors})";
        StatusText.Text = message;
    }

    private bool Matches(object item)
    {
        if (item is not Device d) return false;
        string query = Search.Text.Trim();
        bool text = string.Join(" ", d.Ip, d.Mac, d.Vendor, d.Hostname, d.Model, d.Role).Contains(query, StringComparison.OrdinalIgnoreCase);
        return text && (StatusFilter.SelectedIndex switch
        {
            1 => d.Responded,
            2 => !d.Responded,
            3 => d.Model is not null,
            _ => true
        });
    }

    private void Counts()
    {
        TotalText.Text = devices.Count.ToString();
        RespondedText.Text = devices.Count(d => d.Responded).ToString();
        CacheText.Text = devices.Count(d => !d.Responded).ToString();
    }

    private void Filter_Changed(object sender, TextChangedEventArgs e) => view?.Refresh();
    private void Status_Changed(object sender, SelectionChangedEventArgs e) => view?.Refresh();
    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        devices.Clear();
        Counts();
        resultScope = null;
        resultStatus = "not-scanned";
        partialResults = false;
        DetailTitle.Text = "Select an observation";
        DetailBody.Text = "No current observation selected.";
        RefreshAdapters();
    }
    private void Cancel_Click(object sender, RoutedEventArgs e) => cancellation?.Cancel();
    private void Demo_Click(object sender, RoutedEventArgs e) => LoadDemo();

    private void LoadDemo()
    {
        demo = true;
        Adapters.Tag = "Demo - synthetic observations only";
        ScanProgress.Value = 0;
        resultScope = "DEMO - synthetic";
        resultStatus = "demo";
        partialResults = false;
        errors = 0;
        Errors.Clear();
        ErrorPanel.Header = "Operation notices (0)";
        Adapters.ItemsSource = Array.Empty<Adapter>();
        Cidr.Text = "DEMO - no network I/O";
        ScopeHint.Text = "Synthetic fixture data only. Refresh adapters to leave demo; a real scan still requires confirmation.";
        devices.Clear();
        var now = DateTimeOffset.UtcNow;
        devices.Add(new("192.168.50.1", "00:00:00:00:00:01", "Unknown", "demo-router", null, "Gateway", true, now, now, "DEMO: simulated ICMP + neighbor cache", 2));
        devices.Add(new("192.168.50.20", "02:00:00:00:00:20", "TP-Link (self-reported Kasa)", null, "DEMO HS100", "Device", true, now, now, "DEMO: simulated legacy Kasa get_sysinfo", 8));
        devices.Add(new("192.168.50.31", "02:00:00:00:00:31", "Unknown", null, null, "Device", false, null, now, "DEMO: stale neighbor cache; no response"));
        devices.Add(new("192.168.50.12", null, "Unknown", "demo-workstation", null, "This PC", true, now, now, "DEMO: simulated ICMP response", 1));
        Counts();
        DevicesGrid.SelectedIndex = 0;
        StatusText.Text = "DEMO MODE - all four observations are synthetic. No network calls or adapter enumeration were made.";
    }

    public void VerifyDemo()
    {
        if (!demo || devices.Count != 4 || devices.Count(d => d.Responded) != 3 || devices.Count(d => !d.Responded) != 1)
            throw new InvalidOperationException("Demo startup fixture failed.");
        if (Background is not SolidColorBrush background || background.Color != (Color)ColorConverter.ConvertFromString("#10151F"))
            throw new InvalidOperationException("Dark theme is not applied to the window.");
        if (string.IsNullOrEmpty(System.Windows.Automation.AutomationProperties.GetName(Search)))
            throw new InvalidOperationException("Search accessibility name missing.");
        Search.Text = "HS100";
        if (view.Cast<Device>().Count() != 1) throw new InvalidOperationException("Search binding failed.");
        Search.Clear();
        StatusFilter.SelectedIndex = 2;
        if (view.Cast<Device>().Count() != 1) throw new InvalidOperationException("Status filter failed.");
        StatusFilter.SelectedIndex = 0;
        StatusFilter.IsDropDownOpen = true;
        StatusFilter.UpdateLayout();
        StatusFilter.IsDropDownOpen = false;
        Theme_Click(this, new RoutedEventArgs());
        if (Background is not SolidColorBrush lightBackground || lightBackground.Color != (Color)ColorConverter.ConvertFromString("#F3F6FA"))
            throw new InvalidOperationException("Light theme is not applied to the window.");
        Theme_Click(this, new RoutedEventArgs());
        if (DetailBody.Text.Length < 10) throw new InvalidOperationException("Inspector failed.");
    }

    private void Device_Selected(object sender, SelectionChangedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is not Device d) return;
        DetailTitle.Text = d.DisplayName;
        DetailBody.Text = $"IP ADDRESS\n{d.Ip}\n\nMAC (neighbor evidence only)\n{d.MacDisplay}\n\nVENDOR / CLAIM\n{d.Vendor}\n\nMODEL (self-reported)\n{d.Model ?? "Not available"}\n\nROLE\n{d.Role}\n\nSTATUS\n{d.Status}\n\nLAST RESPONSE (UTC)\n{d.LastSeen?.ToString("u") ?? "Unknown"}\n\nOBSERVED (UTC)\n{d.ObservedAt:u}\n\nLATENCY\n{d.LatencyDisplay}\n\nEVIDENCE\n{d.Evidence}";
    }

    private void Csv_Click(object sender, RoutedEventArgs e) => Save(false);
    private void Json_Click(object sender, RoutedEventArgs e) => Save(true);
    private void Save(bool json)
    {
        if (devices.Count == 0) { Notice("No observations to export."); return; }
        var dialog = new SaveFileDialog
        {
            FileName = $"harbor-{(demo ? "DEMO-" : "")}{DateTime.Now:yyyyMMdd-HHmmss}",
            DefaultExt = json ? ".json" : ".csv",
            Filter = json ? "JSON (*.json)|*.json" : "CSV (*.csv)|*.csv"
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var snapshot = new ScanExport(resultScope, demo, partialResults, resultStatus, errors, devices.OrderBy(d => d.IpNumber).ToArray());
            var content = json ? Export.Json(snapshot) : Export.Csv(snapshot);
            File.WriteAllText(dialog.FileName, content, new UTF8Encoding(true));
            StatusText.Text = $"Exported {snapshot.Devices.Count} {(demo ? "DEMO " : "")}observations. CSV text cells are formula-protected.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Notice($"Export failed: {ex.Message}"); }
    }

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        light = !light;
        string[] keys = ["Background", "Surface", "Foreground", "Muted", "Stroke", "Accent"];
        string[] colors = light
            ? ["#F3F6FA", "#FFFFFF", "#15243B", "#4C6079", "#C9D6E5", "#14745E"]
            : ["#10151F", "#192231", "#EDF3FC", "#A8B9CE", "#344258", "#65D6BE"];
        for (int i = 0; i < keys.Length; i++)
            Application.Current.Resources[keys[i]] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i]));
        ScanButton.Foreground = new SolidColorBrush(light ? Colors.White : (Color)ColorConverter.ConvertFromString("#10251E"));
    }
}
