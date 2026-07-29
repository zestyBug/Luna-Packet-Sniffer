using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using LunaPacketSniffer.App.ViewModels;
using LunaPacketSniffer.Capture;
using LunaPacketSniffer.Core;

namespace LunaPacketSniffer.App;

public partial class FilterWindow : Window
{
    private readonly ObservableCollection<CaptureFilter> _filters;
    private readonly ObservableCollection<ProcessListItem> _processes;

    public FilterWindow(ObservableCollection<CaptureFilter> filters, ObservableCollection<ProcessListItem> processes)
    {
        _filters = filters;
        _processes = processes;
        InitializeComponent();
        FilterListBox.ItemsSource = _filters;
        FilterPidComboBox.ItemsSource = _processes;
        UpdateFilterValueControl();
    }

    private void AddFilterButton_Click(object sender, RoutedEventArgs e)
    {
        if (FilterTypeComboBox.SelectedItem is not ComboBoxItem { Tag: string typeName })
        {
            return;
        }

        try
        {
            var type = Enum.Parse<CaptureFilterType>(typeName);
            var value = type switch
            {
                CaptureFilterType.ProcessId when FilterPidComboBox.SelectedItem is ProcessListItem process => process.ProcessId.ToString(),
                CaptureFilterType.Protocol when FilterProtocolComboBox.SelectedItem is ComboBoxItem { Tag: string protocol } => protocol,
                _ => FilterValueTextBox.Text,
            };
            var filter = CaptureFilter.Create(type, value);
            if (!_filters.Contains(filter))
            {
                _filters.Add(filter);
            }
            FilterValueTextBox.Clear();
            StatusText.Text = "Filter added.";
        }
        catch (ArgumentException exception)
        {
            StatusText.Text = exception.Message;
        }
    }

    private void RemoveFilterButton_Click(object sender, RoutedEventArgs e)
    {
        if (FilterListBox.SelectedItem is CaptureFilter filter)
        {
            _filters.Remove(filter);
        }
    }

    private void FilterTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateFilterValueControl();
    }

    private void UpdateFilterValueControl()
    {
        if (FilterValueTextBox is null || FilterPidComboBox is null || FilterProtocolComboBox is null)
        {
            return;
        }

        if (FilterTypeComboBox.SelectedItem is not ComboBoxItem { Tag: string typeName })
        {
            return;
        }

        var usesPidSelector = typeName == "ProcessId";
        var usesProtocolSelector = typeName == "Protocol";
        FilterValueTextBox.Visibility = usesPidSelector || usesProtocolSelector ? Visibility.Collapsed : Visibility.Visible;
        FilterPidComboBox.Visibility = usesPidSelector ? Visibility.Visible : Visibility.Collapsed;
        FilterProtocolComboBox.Visibility = usesProtocolSelector ? Visibility.Visible : Visibility.Collapsed;
    }

    private void FilterPidComboBox_DropDownOpened(object sender, EventArgs e)
    {
        var processes = Process.GetProcesses()
            .Select(process =>
            {
                using (process)
                {
                    return new ProcessListItem((uint)process.Id, process.ProcessName);
                }
            })
            .OrderBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(process => process.ProcessId)
            .ToArray();

        _processes.Clear();
        foreach (var process in processes)
        {
            _processes.Add(process);
        }
    }
}
