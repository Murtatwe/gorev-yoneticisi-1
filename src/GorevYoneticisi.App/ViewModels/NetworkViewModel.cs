using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using GorevYoneticisi.App.Services;

namespace GorevYoneticisi.App.ViewModels;

public sealed class ConnectionRow : ObservableObject
{
    private ConnectionInfo _info = null!;
    private System.Windows.Media.ImageSource? _icon;

    public required ConnectionInfo Info { get => _info; set { _info = value; OnPropertyChanged(nameof(State)); } }
    public required string ProcessName { get; init; }
    public System.Windows.Media.ImageSource? Icon { get => _icon; set => SetProperty(ref _icon, value); }
    public string Key => $"{Info.Protocol}|{Info.Local}|{Info.Remote}|{Info.Pid}";
    public string Protocol => Info.Protocol;
    public string Local => Info.Local;
    public string Remote => Info.Remote;
    public string State => Info.State;
    public int Pid => Info.Pid;
    public bool IsListening => Info.StateCode == 2 || Info.Protocol.StartsWith("UDP", StringComparison.Ordinal);
}

public sealed class NetworkViewModel : ObservableObject
{
    private readonly DispatcherTimer _timer;
    private Dictionary<int, (string Name, string? Path)> _names = new();
    private bool _isActive, _busy, _showListening = true;
    private string _search = "", _summary = "";

    public NetworkViewModel()
    {
        View = (ListCollectionView)CollectionViewSource.GetDefaultView(Rows);
        View.SortDescriptions.Add(new SortDescription(nameof(ConnectionRow.ProcessName), ListSortDirection.Ascending));
        View.Filter = Filter;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    public ObservableCollection<ConnectionRow> Rows { get; } = new();
    public ListCollectionView View { get; }
    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }

    public string Search { get => _search; set { if (SetProperty(ref _search, value)) View.Refresh(); } }
    public bool ShowListening { get => _showListening; set { if (SetProperty(ref _showListening, value)) View.Refresh(); } }

    public bool IsActive
    {
        get => _isActive;
        set
        {
            if (!SetProperty(ref _isActive, value)) return;
            if (value)
            {
                _timer.Start();
                _ = RefreshAsync();
            }
            else
            {
                _timer.Stop();
            }
        }
    }

    public void UpdateProcessNames(MonitorSnapshot s)
    {
        // Always kept up to date so the first visit to the page already shows names.
        _names = s.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => (g.First().Name, g.First().Path));
    }

    private bool Filter(object o)
    {
        if (o is not ConnectionRow r) return false;
        if (!_showListening && r.IsListening) return false;
        if (_search.Length == 0) return true;
        return r.ProcessName.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || r.Remote.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || r.Local.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || r.Pid.ToString() == _search;
    }

    private async Task RefreshAsync()
    {
        if (_busy) return;
        _busy = true;
        try
        {
            var list = await Task.Run(MonitorService.ReadConnections);
            var names = _names;
            // Update in place (add/remove only what changed) so selection and scroll position survive refreshes.
            var existing = Rows.ToDictionary(r => r.Key);
            var seen = new HashSet<string>();
            foreach (var c in list)
            {
                string key = $"{c.Protocol}|{c.Local}|{c.Remote}|{c.Pid}";
                if (!seen.Add(key)) continue;
                if (existing.TryGetValue(key, out var row))
                {
                    if (row.Info.StateCode != c.StateCode) row.Info = c;
                    continue;
                }
                var (name, path) = names.TryGetValue(c.Pid, out var n) ? n : (c.Pid == 0 ? "Sistem" : c.Pid == 4 ? "System" : $"PID {c.Pid}", null);
                var newRow = new ConnectionRow { Info = c, ProcessName = name };
                newRow.Icon = Ui.IconCache.GetOrQueue(path, img => newRow.Icon = img);
                Rows.Add(newRow);
            }
            foreach (var row in Rows.Where(r => !seen.Contains(r.Key)).ToList()) Rows.Remove(row);

            int established = list.Count(c => c.StateCode == 5);
            int waiting = list.Count(c => c.StateCode == 2 || c.Protocol.StartsWith("UDP", StringComparison.Ordinal));
            Summary = $"{list.Count} bağlantı · {established} etkin · {waiting} tanesi bağlantı bekliyor";
        }
        catch (Exception ex)
        {
            App.Log(ex, "Ağ bağlantıları okunamadı");
        }
        finally
        {
            _busy = false;
        }
    }
}
