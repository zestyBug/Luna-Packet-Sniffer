using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using LunaPacketSniffer.App.Loading;
using LunaPacketSniffer.App.Recording;
using LunaPacketSniffer.App.ViewModels;
using LunaPacketSniffer.Capture;
using LunaPacketSniffer.Protocols;
using LunaPacketSniffer.Proxy;

namespace LunaPacketSniffer.App;

public partial class MainWindow : Window
{
    private const int MaxRowsPerGrid = 10_000;
    private const int MaxListRowsPerTick = 500;
    private const int MaxAggregateRowsPerTick = 1_000;

    private readonly DispatcherTimer _statisticsTimer;
    private readonly RootCertificateAuthority _rootCertificateAuthority = new();
    private readonly HttpsMitmController _httpsMitm;

    private readonly ConcurrentQueue<PacketListItem> _pendingPacketRows = new();
    private readonly ConcurrentQueue<HttpSessionListItem> _pendingHttpRows = new();
    private readonly ConcurrentQueue<WebSocketListItem> _pendingWebSocketRows = new();
    private readonly ConcurrentQueue<FlowUpdate> _pendingFlowUpdates = new();
    private readonly ConcurrentQueue<KcpConversationUpdate> _pendingKcpUpdates = new();

    private readonly ObservableCollection<PacketListItem> _packetRows = [];
    private readonly ObservableCollection<HttpSessionListItem> _httpRows = [];
    private readonly ObservableCollection<WebSocketListItem> _webSocketRows = [];
    private readonly ObservableCollection<FlowSessionListItem> _flowRows = [];
    private readonly Dictionary<string, FlowSessionListItem> _flowRowsByKey = [];
    private readonly ObservableCollection<KcpConversationListItem> _kcpRows = [];
    private readonly Dictionary<string, KcpConversationListItem> _kcpRowsByKey = [];

    private readonly ObservableCollection<CaptureFilter> _filters = [];
    private readonly ObservableCollection<ProcessListItem> _processes = [];

    private CaptureRunner? _captureRunner;
    private FilterWindow? _filterWindow;
    private CertificateWindow? _certificateWindow;
    private string? _loadedCaptureDirectory;

    public MainWindow()
    {
        InitializeComponent();
        PacketGrid.ItemsSource = _packetRows;
        HttpGrid.ItemsSource = _httpRows;
        WebSocketGrid.ItemsSource = _webSocketRows;
        FlowGrid.ItemsSource = _flowRows;
        KcpGrid.ItemsSource = _kcpRows;
        _httpsMitm = new HttpsMitmController(_rootCertificateAuthority);
        _statisticsTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _statisticsTimer.Tick += (_, _) => UpdateStatistics();
    }

    private async void StartButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ApplicationLog.Write("Capture start requested.");
            ClearGrids();
            StatusText.Text = "Creating capture files";

            var runner = await CaptureRunner.CreateAsync(CaptureOutput.CreateCaptureDirectory(), _filters);
            _captureRunner = runner;
            runner.PacketObserved += _pendingPacketRows.Enqueue;
            runner.FlowObserved += _pendingFlowUpdates.Enqueue;
            runner.KcpConversationObserved += _pendingKcpUpdates.Enqueue;
            runner.HttpTransactionObserved += transaction => _pendingHttpRows.Enqueue(HttpSessionListItem.Create(transaction));
            runner.WebSocketMessageObserved += message => _pendingWebSocketRows.Enqueue(WebSocketListItem.Create(message));

            _httpsMitm.Start(runner.HarWriter, _filters);
            StatusText.Text = "Opening WinDivert";
            ApplicationLog.Write("Opening WinDivert.");
            runner.Start();

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            StatusText.Text = "Capturing";
            DetailTextBox.Text = $"Capture output: {runner.OutputDirectory}";
            ApplicationLog.Write($"Capture started. Output: {runner.OutputDirectory}");
            _statisticsTimer.Start();
        }
        catch (Exception exception)
        {
            ApplicationLog.Write(exception);
            await ShutdownCaptureAsync();
            StatusText.Text = $"{exception.GetType().Name}: {exception.Message}";
            DetailTextBox.Text = exception.ToString();
        }
    }

    private async void StopButton_Click(object sender, RoutedEventArgs e)
    {
        if (_captureRunner is not { } runner)
        {
            return;
        }

        StopButton.IsEnabled = false;
        StatusText.Text = "Finalizing capture";
        ApplicationLog.Write("Capture stop requested.");
        _statisticsTimer.Stop();

        await ShutdownCaptureAsync();

        StatusText.Text = $"Saved {runner.CapturedPacketCount:N0} packets";
        ApplicationLog.Write($"Capture stopped. Packets: {runner.CapturedPacketCount}");
        StartButton.IsEnabled = true;
    }

    protected override async void OnClosed(EventArgs e)
    {
        await ShutdownCaptureAsync();
        base.OnClosed(e);
    }

    /// <summary>Restores the Windows proxy setting and closes the capture files. Safe when nothing is running.</summary>
    private async ValueTask ShutdownCaptureAsync()
    {
        await _httpsMitm.StopAsync();
        if (_captureRunner is { } runner)
        {
            _captureRunner = null;
            await runner.StopAsync();
        }
    }

    private void OpenFiltersMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_filterWindow is null)
        {
            _filterWindow = new FilterWindow(_filters, _processes) { Owner = this };
            _filterWindow.Closed += (_, _) => _filterWindow = null;
            _filterWindow.Show();
            return;
        }

        _filterWindow.Activate();
    }

    private void OpenCertificatesMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_certificateWindow is null)
        {
            _certificateWindow = new CertificateWindow(_rootCertificateAuthority) { Owner = this };
            _certificateWindow.Closed += (_, _) => _certificateWindow = null;
            _certificateWindow.Show();
            return;
        }

        _certificateWindow.Activate();
    }

    private void OpenCaptureMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_captureRunner is not null)
        {
            StatusText.Text = "Stop the active capture before loading another capture.";
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = "Select a LunaPacketSniffer capture folder",
            InitialDirectory = CaptureOutput.RootDirectory,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            LoadCapture(dialog.FolderName);
        }
        catch (Exception exception) when (exception is IOException or SqliteException or InvalidDataException)
        {
            ApplicationLog.Write(exception);
            StatusText.Text = $"Could not load capture: {exception.Message}";
            DetailTextBox.Text = exception.ToString();
        }
    }

    private void OpenOutputFolderMenuItem_Click(object sender, RoutedEventArgs e)
    {
        var directory = _loadedCaptureDirectory ?? CaptureOutput.RootDirectory;
        Directory.CreateDirectory(directory);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{directory}\"") { UseShellExecute = true });
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void LoadCapture(string directory)
    {
        var capture = CaptureLoader.Load(directory);
        ClearGrids();
        AddRange(_packetRows, capture.Packets);
        AddRange(_httpRows, capture.HttpTransactions);
        AddRange(_webSocketRows, capture.WebSocketMessages);
        AddRange(_flowRows, capture.Flows);
        AddRange(_kcpRows, capture.KcpConversations);

        _loadedCaptureDirectory = directory;
        StatusText.Text = $"Loaded {Path.GetFileName(directory)}";
        DetailTextBox.Text = $"Loaded capture: {directory}";
    }

    private void ClearGrids()
    {
        _packetRows.Clear();
        _pendingPacketRows.Clear();
        _httpRows.Clear();
        _pendingHttpRows.Clear();
        _webSocketRows.Clear();
        _pendingWebSocketRows.Clear();
        _flowRows.Clear();
        _flowRowsByKey.Clear();
        _pendingFlowUpdates.Clear();
        _kcpRows.Clear();
        _kcpRowsByKey.Clear();
        _pendingKcpUpdates.Clear();
    }

    private void UpdateStatistics()
    {
        ScrollToLatest(PacketGrid, PendingRowQueue.Drain(_pendingPacketRows, _packetRows, MaxListRowsPerTick, MaxRowsPerGrid));
        ScrollToLatest(HttpGrid, PendingRowQueue.Drain(_pendingHttpRows, _httpRows, MaxListRowsPerTick, MaxRowsPerGrid));
        ScrollToLatest(WebSocketGrid, PendingRowQueue.Drain(_pendingWebSocketRows, _webSocketRows, MaxListRowsPerTick, MaxRowsPerGrid));
        ScrollToLatest(FlowGrid, PendingRowQueue.DrainKeyed(
            _pendingFlowUpdates,
            _flowRows,
            _flowRowsByKey,
            MaxAggregateRowsPerTick,
            update => update.Key,
            update => new FlowSessionListItem(update.Flow),
            (row, update) => row.AddPacket(update)));
        ScrollToLatest(KcpGrid, PendingRowQueue.DrainKeyed(
            _pendingKcpUpdates,
            _kcpRows,
            _kcpRowsByKey,
            MaxAggregateRowsPerTick,
            update => $"{update.ConversationId}:{update.EndpointA}:{update.EndpointB}",
            update => new KcpConversationListItem(update),
            (row, update) => row.Update(update)));

        if (_captureRunner is { } runner)
        {
            StatusText.Text = $"Capturing {runner.CapturedPacketCount:N0} packets";
        }
    }

    private void ScrollToLatest(DataGrid grid, object? item)
    {
        if (AutoScrollToggleButton.IsChecked == true && item is not null)
        {
            grid.ScrollIntoView(item);
        }
    }

    private static void AddRange<T>(ObservableCollection<T> rows, IReadOnlyList<T> items)
    {
        foreach (var item in items)
        {
            rows.Add(item);
        }
    }

    private void PacketGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PacketGrid.SelectedItem is PacketListItem item)
        {
            DetailTextBox.Text = item.GetDetail();
        }
    }

    private void HttpGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HttpGrid.SelectedItem is HttpSessionListItem item)
        {
            DetailTextBox.Text = item.GetDetail();
        }
    }

    private void WebSocketGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (WebSocketGrid.SelectedItem is WebSocketListItem item)
        {
            DetailTextBox.Text = item.Detail;
        }
    }

    private void FlowGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FlowGrid.SelectedItem is FlowSessionListItem item)
        {
            DetailTextBox.Text = item.GetDetail();
        }
    }

    private void KcpGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (KcpGrid.SelectedItem is KcpConversationListItem item)
        {
            DetailTextBox.Text = item.Detail;
        }
    }
}
