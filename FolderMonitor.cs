using System.Diagnostics;
using System.Drawing;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows.Forms;

namespace UpdateDetective;

record FolderFile(string RelativePath, long Bytes, DateTime ModifiedUtc, string Sha256);
record FolderSnapshot(DateTime CapturedUtc, List<FolderFile> Files, int SkippedLinks);
record FolderEntry(string Root, FolderSnapshot Baseline, FolderSnapshot? Latest, string? Error = null);
record FolderChange(string Path, string Kind, FolderFile? Before, FolderFile? After);

static class FolderInspector
{
    // A scan is deliberately rejected if any ordinary file or directory cannot be read.
    // This prevents inaccessible files from being reported as deleted.
    public static FolderSnapshot Capture(string root)
    {
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Choose a real folder, not a junction or symbolic link.");
        var files = new List<FolderFile>();
        var pending = new Stack<string>();
        pending.Push(root);
        int skipped = 0, visited = 0;
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(dir))
            {
                if (++visited > 50000) throw new IOException("Folder exceeds the 50,000-entry safety limit. Choose a smaller application folder.");
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0) { skipped++; continue; }
                if ((attributes & FileAttributes.Directory) != 0) { pending.Push(path); continue; }
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.SequentialScan);
                var hash = Convert.ToHexString(SHA256.HashData(stream));
                files.Add(new(Path.GetRelativePath(root, path), stream.Length, File.GetLastWriteTimeUtc(path), hash));
            }
        }
        return new(DateTime.UtcNow, files.OrderBy(x => x.RelativePath, StringComparer.OrdinalIgnoreCase).ToList(), skipped);
    }

    public static List<FolderChange> Compare(FolderSnapshot baseline, FolderSnapshot latest)
    {
        // Ordinal comparison preserves case-only names even in case-sensitive NTFS directories.
        var old = baseline.Files.ToDictionary(x => x.RelativePath, StringComparer.Ordinal);
        var now = latest.Files.ToDictionary(x => x.RelativePath, StringComparer.Ordinal);
        var result = new List<FolderChange>();
        foreach (var f in latest.Files)
        {
            if (!old.TryGetValue(f.RelativePath, out var previous)) result.Add(new(f.RelativePath, "Added", null, f));
            else if (previous.Sha256 != f.Sha256) result.Add(new(f.RelativePath, "Modified", previous, f));
            else if (previous.ModifiedUtc != f.ModifiedUtc) result.Add(new(f.RelativePath, "Timestamp only", previous, f));
        }
        foreach (var f in baseline.Files)
            if (!now.ContainsKey(f.RelativePath)) result.Add(new(f.RelativePath, "Deleted", f, null));
        return result.OrderBy(x => x.Kind).ThenBy(x => x.Path).ToList();
    }
}

sealed class FolderPanel : UserControl
{
    static readonly Color Bg = Color.FromArgb(13,19,29), Surface = Color.FromArgb(22,31,45), Ink = Color.FromArgb(231,239,248), Muted = Color.FromArgb(151,170,192), Accent = Color.FromArgb(64,190,224);
    readonly string store = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UpdateDetective", "folders.json");
    readonly List<FolderEntry> entries = new();
    readonly ListView folders = new(), changes = new();
    readonly FlowLayoutPanel actions = new();
    readonly Label summary = new(), status = new();
    readonly CheckBox auto = new() { Text = "Scan every 5 min while open", AutoSize = true, Checked = true };
    readonly System.Windows.Forms.Timer timer = new() { Interval = 300000 };
    readonly ComboBox filter = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
    bool advanced, ready, busy;
    public bool IsBusy => busy;

    public FolderPanel()
    {
        Dock = DockStyle.Fill; BackColor = Bg; ForeColor = Ink; Font = new("Segoe UI", 10);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(12), ColumnCount = 1, RowCount = 5 };
        layout.RowStyles.Add(new(SizeType.Absolute, 52)); layout.RowStyles.Add(new(SizeType.Absolute, 44));
        layout.RowStyles.Add(new(SizeType.Percent, 38)); layout.RowStyles.Add(new(SizeType.Percent, 62)); layout.RowStyles.Add(new(SizeType.Absolute, 48));
        Controls.Add(layout);
        actions.Dock = DockStyle.Fill; actions.AutoScroll = true; actions.WrapContents = false;
        layout.Controls.Add(actions,0,0);
        Button("+ Add installation", AddFolder); Button("Scan all", ScanAll); Button("Accept baseline", Accept); Button("Stop tracking", Remove); Button("Export report", Export);
        auto.ForeColor = Muted; auto.Margin = new(12,9,0,0); actions.Controls.Add(auto);
        var bar = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        summary.AutoSize = true; summary.ForeColor = Accent; summary.Margin = new(0,8,20,0); bar.Controls.Add(summary);
        filter.Items.AddRange(new object[] {"All changes","Added","Modified","Deleted","Timestamp only"}); filter.SelectedIndex = 0; bar.Controls.Add(filter);
        layout.Controls.Add(bar,0,1);
        Style(folders); folders.Columns.Add("Installation folder",510); folders.Columns.Add("Files",100); folders.Columns.Add("Result",280); folders.Columns.Add("Last scan (UTC)",180);
        Style(changes); changes.Columns.Add("Change",140); changes.Columns.Add("Relative file path",480); changes.Columns.Add("Before bytes",110); changes.Columns.Add("After bytes",110); changes.Columns.Add("Before SHA-256",500); changes.Columns.Add("After SHA-256",500);
        layout.Controls.Add(folders,0,2); layout.Controls.Add(changes,0,3);
        status.Dock = DockStyle.Fill; status.ForeColor = Muted; layout.Controls.Add(status,0,4);
        folders.SelectedIndexChanged += (_,_) => ShowChanges(); filter.SelectedIndexChanged += (_,_) => ShowChanges();
        auto.CheckedChanged += (_,_) => timer.Enabled = ready && auto.Checked;
        timer.Tick += async (_,_) => await Run(ScanAll);
        try
        {
            if (File.Exists(store)) entries.AddRange(JsonSerializer.Deserialize<List<FolderEntry>>(File.ReadAllText(store)) ?? throw new InvalidDataException("Invalid folder snapshots"));
            ready = true; status.Text = "Choose an application installation directory. Scans hash readable files; links and junctions are excluded.";
        }
        catch (Exception ex) { status.Text = "Cannot read folder database; it has not been replaced. " + ex.Message; actions.Enabled = false; }
        timer.Enabled = ready && auto.Checked;
        SetAdvanced(false); RefreshRows();
    }

    protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }
    void Style(ListView v) { v.Dock = DockStyle.Fill; v.View = View.Details; v.FullRowSelect = true; v.MultiSelect = false; v.HideSelection = false; v.BackColor = Surface; v.ForeColor = Ink; v.BorderStyle = BorderStyle.None; }
    void Button(string name, Func<Task> action)
    {
        var button = new Button { Text = name, AutoSize = true, Height = 36, FlatStyle = FlatStyle.Flat, BackColor = Surface, ForeColor = Ink, Margin = new(0,0,8,0) };
        button.Click += async (_,_) => await Run(action); actions.Controls.Add(button);
    }
    async Task Run(Func<Task> work)
    {
        if (busy || !ready) return;
        busy = true; actions.Enabled = false;
        try { await work(); }
        catch (Exception ex) { status.Text = "Operation failed: " + ex.Message; }
        finally { busy = false; actions.Enabled = ready; }
    }
    void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(store)!);
        File.WriteAllText(store+".tmp", JsonSerializer.Serialize(entries));
        File.Move(store+".tmp",store,true);
    }
    FolderEntry? Selected => folders.SelectedItems.Count == 0 ? null : folders.SelectedItems[0].Tag as FolderEntry;
    public void SetAdvanced(bool value)
    {
        advanced = value; changes.Columns[4].Width = value ? 500 : 0; changes.Columns[5].Width = value ? 500 : 0;
        ShowChanges();
    }
    void RefreshRows()
    {
        var selected = Selected?.Root;
        folders.BeginUpdate(); folders.Items.Clear();
        foreach (var entry in entries)
        {
            var diff = entry.Latest is null ? null : FolderInspector.Compare(entry.Baseline, entry.Latest);
            string result = entry.Error != null ? "Scan incomplete" : diff == null ? "Baseline saved" : diff.Count == 0 ? "Unchanged" : $"{diff.Count} change(s) observed";
            var row = new ListViewItem(new[] {entry.Root, (entry.Latest?.Files.Count ?? entry.Baseline.Files.Count).ToString("N0"), result, entry.Latest?.CapturedUtc.ToString("u") ?? "Not scanned"}) { Tag = entry };
            if (entry.Error != null || diff?.Count > 0) row.ForeColor = Color.FromArgb(255,193,102);
            folders.Items.Add(row); if (entry.Root == selected) row.Selected = true;
        }
        if (folders.SelectedItems.Count == 0 && folders.Items.Count > 0) folders.Items[0].Selected = true;
        folders.EndUpdate();
        summary.Text = $"{entries.Count} installation(s)  |  {entries.Count(e => e.Error != null)} incomplete";
        ShowChanges();
    }
    void ShowChanges()
    {
        changes.BeginUpdate(); changes.Items.Clear();
        var entry = Selected;
        if (entry?.Latest != null && entry.Error == null)
        {
            foreach (var change in FolderInspector.Compare(entry.Baseline,entry.Latest))
            {
                if (filter.SelectedIndex > 0 && change.Kind != (string?)filter.SelectedItem) continue;
                var row = new ListViewItem(new[] {change.Kind,change.Path,change.Before?.Bytes.ToString("N0") ?? "—",change.After?.Bytes.ToString("N0") ?? "—",advanced ? change.Before?.Sha256 ?? "—" : "",advanced ? change.After?.Sha256 ?? "—" : ""});
                row.ForeColor = change.Kind == "Added" ? Color.FromArgb(100,220,155) : change.Kind == "Deleted" ? Color.FromArgb(255,125,125) : Color.FromArgb(255,193,102);
                changes.Items.Add(row);
            }
        }
        changes.EndUpdate();
        if (entry?.Error != null) status.Text = "Incomplete scan; baseline preserved. " + entry.Error;
        else if (entry?.Latest != null) status.Text = $"Compared {entry.Latest.Files.Count:N0} files. {entry.Latest.SkippedLinks} link(s) excluded. Changes do not prove an update or malware.";
    }
    async Task AddFolder()
    {
        using var dialog = new FolderBrowserDialog { Description = "Select one application installation folder", UseDescriptionForTitle = true, ShowNewFolderButton = false };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dialog.SelectedPath));
        if (string.Equals(root, Path.TrimEndingDirectorySeparator(Path.GetPathRoot(root)!), StringComparison.OrdinalIgnoreCase)) { status.Text = "Select an application folder rather than an entire drive."; return; }
        if (entries.Any(e => string.Equals(e.Root,root,StringComparison.OrdinalIgnoreCase))) { status.Text = "This installation is already tracked."; return; }
        // Do not monitor our own database or its ancestors.
        var dataDir = Path.GetDirectoryName(store)!;
        if (string.Equals(root,dataDir,StringComparison.OrdinalIgnoreCase) || dataDir.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || root.StartsWith(dataDir+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) { status.Text = "Choose a folder outside Update Detective's data directory."; return; }
        status.Text = "Capturing baseline: " + root;
        var baseline = await Task.Run(() => FolderInspector.Capture(root));
        entries.Add(new(root,baseline,null)); Save(); RefreshRows();
        status.Text = $"Baseline captured: {baseline.Files.Count:N0} files; {baseline.SkippedLinks} link(s) excluded.";
    }
    async Task ScanAll()
    {
        if (entries.Count == 0) return;
        for (int i = 0; i < entries.Count; i++)
        {
            var entry = entries[i]; status.Text = "Scanning: " + entry.Root;
            try { var snapshot = await Task.Run(() => FolderInspector.Capture(entry.Root)); entries[i] = entry with {Latest = snapshot, Error = null}; }
            catch (Exception ex) { entries[i] = entry with {Error = ex.Message}; }
        }
        Save(); RefreshRows();
        int complete = entries.Count(e => e.Error == null && e.Latest != null);
        int changed = entries.Count(e => e.Error == null && e.Latest != null && FolderInspector.Compare(e.Baseline,e.Latest).Count != 0);
        status.Text = $"Scan complete: {complete}/{entries.Count} successful, {changed} changed installation(s). Baselines preserved.";
    }
    Task Accept()
    {
        var entry = Selected; if (entry?.Latest == null || entry.Error != null) { status.Text = "Select a successful scan first."; return Task.CompletedTask; }
        if (MessageBox.Show(this,"Replace this installation baseline? Export first to preserve the comparison.","Accept baseline",MessageBoxButtons.YesNo,MessageBoxIcon.Question) == DialogResult.Yes)
        { entries[entries.IndexOf(entry)] = new(entry.Root,entry.Latest,null); Save(); RefreshRows(); }
        return Task.CompletedTask;
    }
    Task Remove()
    {
        var entry = Selected; if (entry != null && MessageBox.Show(this,"Stop monitoring this folder? No application files will be deleted.","Stop tracking",MessageBoxButtons.YesNo) == DialogResult.Yes)
        { entries.Remove(entry); Save(); RefreshRows(); }
        return Task.CompletedTask;
    }
    Task Export()
    {
        using var dialog = new SaveFileDialog { Filter = "JSON (*.json)|*.json", FileName = "UpdateDetective-folders-report.json" };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var report = entries.Select(e => new { e.Root,e.Baseline,e.Latest,e.Error, Changes = e.Error == null && e.Latest != null ? FolderInspector.Compare(e.Baseline,e.Latest) : null });
            File.WriteAllText(dialog.FileName,JsonSerializer.Serialize(new {GeneratedUtc=DateTime.UtcNow,Installations=report},new JsonSerializerOptions {WriteIndented=true}));
            status.Text = "Report saved locally. Review private file paths before sharing.";
        }
        return Task.CompletedTask;
    }
}
