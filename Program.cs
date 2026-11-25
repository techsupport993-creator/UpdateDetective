using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Win32;
using System.Drawing;
using System.Windows.Forms;

namespace UpdateDetective;

record Snapshot(string Path, string Version, string ProductVersion, string Company, long Size, DateTime ModifiedUtc, string Hash, string Signature, string Signer, string SignerThumbprint, DateTime CapturedUtc);
record Entry(Snapshot Baseline, Snapshot? Latest);
record Candidate(string Name, string Path);

static class Program {
    [STAThread] static void Main() { ApplicationConfiguration.Initialize(); Application.Run(new MainWindow()); }
}

static class Inspector {
    public static Snapshot Read(string path) {
        path = System.IO.Path.GetFullPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var info = new FileInfo(path); var version = FileVersionInfo.GetVersionInfo(path);
        string hash = Convert.ToHexString(SHA256.HashData(stream));
        string signer = "Not available", thumbprint = "Not available";
        try { using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)); signer = cert.Subject; thumbprint = cert.Thumbprint; } catch (CryptographicException) { }
        return new(path, version.FileVersion ?? "Unknown", version.ProductVersion ?? "Unknown", version.CompanyName ?? "Unknown", stream.Length, info.LastWriteTimeUtc, hash, Verify(path), signer, thumbprint, DateTime.UtcNow);
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct FileInfoNative { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr File; public IntPtr KnownSubject; }
    [StructLayout(LayoutKind.Sequential)] struct TrustData { public uint Size; public IntPtr Policy; public IntPtr SIP; public uint UI; public uint Revocation; public uint Union; public IntPtr File; public uint StateAction; public IntPtr State; public IntPtr URL; public uint Flags; public uint UIContext; public IntPtr SignatureSettings; }
    [DllImport("wintrust.dll", ExactSpelling=true)] static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref TrustData data);
    static string Verify(string path) {
        var file = new FileInfoNative { Size=(uint)Marshal.SizeOf<FileInfoNative>(), Path=path };
        IntPtr ptr=Marshal.AllocHGlobal(Marshal.SizeOf<FileInfoNative>());
        try {
            Marshal.StructureToPtr(file,ptr,false);
            var data=new TrustData { Size=(uint)Marshal.SizeOf<TrustData>(), UI=2, Revocation=0, Union=1, File=ptr, StateAction=1, Flags=0x1000|0x10 };
            var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            int result;
            try { result=WinVerifyTrust(new IntPtr(-1),ref action,ref data); }
            finally { data.StateAction=2; WinVerifyTrust(new IntPtr(-1),ref action,ref data); }
            return unchecked((uint)result) switch { 0 => "Trusted (offline; revocation not checked)", 0x800B0100 => "No embedded signature verified", 0x80096010 => "Invalid signature / digest mismatch", 0x800B0109 => "Untrusted root", _ => $"Not verified (0x{unchecked((uint)result):X8})" };
        } finally { Marshal.DestroyStructure<FileInfoNative>(ptr); Marshal.FreeHGlobal(ptr); }
    }
    public static List<Candidate> Discover() {
        var result=new Dictionary<string,Candidate>(StringComparer.OrdinalIgnoreCase);
        foreach(var hive in new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser}) foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}) {
            try { using var root=RegistryKey.OpenBaseKey(hive,view); using var key=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"); if(key==null)continue;
                foreach(var sub in key.GetSubKeyNames()) { try { using var app=key.OpenSubKey(sub); var name=app?.GetValue("DisplayName") as string; var icon=app?.GetValue("DisplayIcon") as string; if(string.IsNullOrWhiteSpace(name)||string.IsNullOrWhiteSpace(icon))continue;
                    var p=Environment.ExpandEnvironmentVariables(icon.Trim()); int end=p.IndexOf(".exe",StringComparison.OrdinalIgnoreCase); if(end<0)continue; p=p[..(end+4)].Trim('"',' '); if(Path.IsPathFullyQualified(p)&&File.Exists(p))result.TryAdd(p,new(name,p));
                } catch { } }
            } catch { }
        }
        return result.Values.OrderBy(x=>x.Name).ToList();
    }
}

sealed class MainWindow : Form {
    static readonly Color Bg=Color.FromArgb(13,19,29), PanelColor=Color.FromArgb(22,31,45), Ink=Color.FromArgb(231,239,248), Muted=Color.FromArgb(151,170,192), Accent=Color.FromArgb(64,190,224);
    readonly string store=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"UpdateDetective","snapshots.json");
    readonly List<Entry> entries=new(); readonly ListView list=new(); readonly ListView details=new(); readonly Label status=new(), headline=new(), stats=new(); readonly FlowLayoutPanel actions=new(); readonly System.Windows.Forms.Timer timer=new(){Interval=300000}; readonly CheckBox auto=new(){Text="Check every 5 min while open",AutoSize=true}; bool busy, ready;
    public MainWindow() {
        Text="Update Detective | 1.1.0"; Size=new(1220,780); MinimumSize=new(940,590); StartPosition=FormStartPosition.CenterScreen; BackColor=Bg; ForeColor=Ink; Font=new("Segoe UI",10);
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new(20),ColumnCount=1,RowCount=6}; layout.RowStyles.Add(new(SizeType.Absolute,82)); layout.RowStyles.Add(new(SizeType.Absolute,46)); layout.RowStyles.Add(new(SizeType.Absolute,46)); layout.RowStyles.Add(new(SizeType.Percent,100)); layout.RowStyles.Add(new(SizeType.Absolute,28)); layout.RowStyles.Add(new(SizeType.Absolute,30)); Controls.Add(layout);
        var header=new Panel{Dock=DockStyle.Fill}; var title=new Label{Text="UPDATE DETECTIVE",Font=new("Segoe UI Semibold",25),ForeColor=Accent,AutoSize=true,Location=new(0,0)}; var sub=new Label{Text="01 / SOFTWARE INTEGRITY     •     Local-only executable change monitoring",ForeColor=Muted,AutoSize=true,Location=new(3,48)}; header.Controls.AddRange(new Control[]{title,sub}); layout.Controls.Add(header,0,0);
        actions.Dock=DockStyle.Fill; actions.WrapContents=false; actions.AutoScroll=true; layout.Controls.Add(actions,0,1);
        AddButton("+ Add executable",async()=>await AddFile()); AddButton("Discover apps",async()=>await Discover()); AddButton("Scan all",async()=>await Scan()); AddButton("Accept baseline",()=>{Accept();return Task.CompletedTask;}); AddButton("Remove",()=>{Remove();return Task.CompletedTask;}); AddButton("Export JSON",()=>{Export();return Task.CompletedTask;});
        var summary=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false,Padding=new(0,8,0,0)}; stats.AutoSize=true; stats.ForeColor=Accent; auto.ForeColor=Muted; auto.Margin=new(24,3,0,0); summary.Controls.Add(stats);summary.Controls.Add(auto); layout.Controls.Add(summary,0,2);
        var split=new SplitContainer{Dock=DockStyle.Fill,Orientation=Orientation.Horizontal,BackColor=Bg,SplitterWidth=8}; layout.Controls.Add(split,0,3); split.HandleCreated+=(_,_)=>{if(split.Height>200)split.SplitterDistance=split.Height/2;};
        StyleList(list); list.Columns.Add("Executable",220);list.Columns.Add("Baseline version",155);list.Columns.Add("Observed version",155);list.Columns.Add("Result",180);list.Columns.Add("Path",430); split.Panel1.Controls.Add(list);
        var detailPanel=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=2};detailPanel.RowStyles.Add(new(SizeType.Absolute,35));detailPanel.RowStyles.Add(new(SizeType.Percent,100)); headline.Dock=DockStyle.Fill; headline.ForeColor=Accent; headline.Text="Select an executable to inspect its evidence";detailPanel.Controls.Add(headline,0,0);StyleList(details);details.Columns.Add("Evidence",170);details.Columns.Add("Baseline",420);details.Columns.Add("Latest observation",420);detailPanel.Controls.Add(details,0,1);split.Panel2.Controls.Add(detailPanel);
        list.SelectedIndexChanged+=(_,_)=>ShowDetails(); status.Dock=DockStyle.Fill;status.ForeColor=Muted;layout.Controls.Add(status,0,4);layout.Controls.Add(new Label{Text="Read-only monitoring • No telemetry • Changes are not proof of malware • Signatures checked offline",ForeColor=Muted,Dock=DockStyle.Fill},0,5);
        auto.CheckedChanged+=(_,_)=>timer.Enabled=auto.Checked;timer.Tick+=async(_,_)=>await Scan(); FormClosing+=(_,e)=>{if(busy){e.Cancel=true;status.Text="A scan is active. Close after it completes.";}};
        try { if(File.Exists(store))entries.AddRange(JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(store))??throw new InvalidDataException("Invalid snapshot data")); ready=true;status.Text="Ready. Add or discover an executable to capture its first baseline."; } catch(Exception ex){status.Text="Cannot load snapshot database: "+ex.Message;MessageBox.Show("Snapshot database could not be loaded. It has not been overwritten. Repair or move this file and restart:\n"+store);actions.Enabled=false;auto.Enabled=false;}
        RefreshList();
    }
    void StyleList(ListView v){v.Dock=DockStyle.Fill;v.View=View.Details;v.FullRowSelect=true;v.MultiSelect=false;v.HideSelection=false;v.BackColor=PanelColor;v.ForeColor=Ink;v.BorderStyle=BorderStyle.None;}
    void AddButton(string label,Func<Task> action){var b=new Button{Text=label,AutoSize=true,Height=34,FlatStyle=FlatStyle.Flat,BackColor=PanelColor,ForeColor=Ink,Padding=new(7,0,7,0),Margin=new(0,0,8,0)};b.FlatAppearance.BorderColor=Color.FromArgb(53,74,94);b.Click+=async(_,_)=>{if(busy||!ready)return;try{await action();}catch(Exception ex){status.Text=ex.Message;MessageBox.Show(ex.Message,"Update Detective",MessageBoxButtons.OK,MessageBoxIcon.Warning);}};actions.Controls.Add(b);}
    async Task Work(Func<Task> task){if(busy||!ready)return;busy=true;actions.Enabled=false;try{await task();}finally{busy=false;actions.Enabled=true;}}
    void Save(){Directory.CreateDirectory(Path.GetDirectoryName(store)!);string tmp=store+".tmp";File.WriteAllText(tmp,JsonSerializer.Serialize(entries,new JsonSerializerOptions{WriteIndented=true}));File.Move(tmp,store,true);}
    Entry? Selected()=>list.SelectedItems.Count>0?list.SelectedItems[0].Tag as Entry:null;
    static string Result(Entry e)=>e.Latest==null?"Baseline only":e.Baseline.Hash!=e.Latest.Hash?"Binary changed":e.Baseline.Signature!=e.Latest.Signature||e.Baseline.SignerThumbprint!=e.Latest.SignerThumbprint?"Trust status changed":e.Baseline.ModifiedUtc!=e.Latest.ModifiedUtc?"Timestamp changed":"Unchanged";
    void RefreshList(){string? selected=Selected()?.Baseline.Path;list.BeginUpdate();list.Items.Clear();foreach(var e in entries){var i=new ListViewItem(new[]{Path.GetFileName(e.Baseline.Path),e.Baseline.Version,e.Latest?.Version??"—",Result(e),e.Baseline.Path}){Tag=e}; if(Result(e).Contains("changed",StringComparison.Ordinal))i.ForeColor=Color.FromArgb(255,193,102);list.Items.Add(i);if(e.Baseline.Path==selected)i.Selected=true;}list.EndUpdate();stats.Text=$"TRACKED  {entries.Count}     |     CHANGED  {entries.Count(e=>Result(e).Contains("changed",StringComparison.Ordinal))}";ShowDetails();}
    void ShowDetails(){details.Items.Clear();var e=Selected();if(e==null){headline.Text="Select an executable to inspect its evidence";return;}var a=e.Baseline;var b=e.Latest;headline.Text=$"{Path.GetFileName(a.Path)}  /  {Result(e)}";void Row(string name,string x,string? y){var item=new ListViewItem(new[]{name,x,y??"Not scanned"});if(y!=null&&x!=y&&name!="Captured (UTC)")item.ForeColor=Color.FromArgb(255,193,102);details.Items.Add(item);}Row("File version",a.Version,b?.Version);Row("Product version",a.ProductVersion,b?.ProductVersion);Row("Company (metadata)",a.Company,b?.Company);Row("Size (bytes)",a.Size.ToString("N0"),b?.Size.ToString("N0"));Row("SHA-256",a.Hash,b?.Hash);Row("Signature verification",a.Signature,b?.Signature);Row("Certificate subject",a.Signer,b?.Signer);Row("Certificate thumbprint",a.SignerThumbprint,b?.SignerThumbprint);Row("Modified (UTC)",a.ModifiedUtc.ToString("u"),b?.ModifiedUtc.ToString("u"));Row("Captured (UTC)",a.CapturedUtc.ToString("u"),b?.CapturedUtc.ToString("u"));}
    async Task AddFile(){using var dialog=new OpenFileDialog{Filter="Windows executables (*.exe)|*.exe",Multiselect=true,CheckFileExists=true};if(dialog.ShowDialog(this)==DialogResult.OK)await AddPaths(dialog.FileNames);}
    async Task AddPaths(IEnumerable<string> paths){await Work(async()=>{int count=0;var errors=new List<string>();foreach(var p in paths.Distinct(StringComparer.OrdinalIgnoreCase)){if(entries.Any(e=>string.Equals(e.Baseline.Path,p,StringComparison.OrdinalIgnoreCase)))continue;status.Text="Capturing "+Path.GetFileName(p);try{var snap=await Task.Run(()=>Inspector.Read(p));entries.Add(new(snap,null));count++;}catch(Exception ex){errors.Add(Path.GetFileName(p)+": "+ex.Message);}}Save();RefreshList();status.Text=$"Added {count} baseline(s). {errors.Count} failed.";if(errors.Count>0)MessageBox.Show(string.Join("\n",errors),"Capture errors");});}
    async Task Discover(){List<Candidate> candidates=new();await Work(async()=>{status.Text="Searching installed application registry entries…";candidates=await Task.Run(Inspector.Discover);});using var dialog=new Form{Text="Choose installed applications",Size=new(780,520),StartPosition=FormStartPosition.CenterParent,BackColor=Bg,ForeColor=Ink};var box=new CheckedListBox{Dock=DockStyle.Fill,BackColor=PanelColor,ForeColor=Ink,CheckOnClick=true};foreach(var c in candidates.Where(c=>!entries.Any(e=>string.Equals(e.Baseline.Path,c.Path,StringComparison.OrdinalIgnoreCase))))box.Items.Add(c.Name+"  |  "+c.Path);var visible=candidates.Where(c=>!entries.Any(e=>string.Equals(e.Baseline.Path,c.Path,StringComparison.OrdinalIgnoreCase))).ToList();var button=new Button{Text="Capture selected baselines",Dock=DockStyle.Bottom,Height=42,DialogResult=DialogResult.OK,BackColor=PanelColor,ForeColor=Ink};dialog.Controls.Add(box);dialog.Controls.Add(button);dialog.AcceptButton=button;if(dialog.ShowDialog(this)==DialogResult.OK)await AddPaths(box.CheckedIndices.Cast<int>().Select(i=>visible[i].Path).ToArray());}
    async Task Scan(){try{await Work(async()=>{int count=0;var errors=new List<string>();for(int i=0;i<entries.Count;i++){var e=entries[i];status.Text="Checking "+Path.GetFileName(e.Baseline.Path);try{var snap=await Task.Run(()=>Inspector.Read(e.Baseline.Path));entries[i]=e with{Latest=snap};count++;}catch(Exception ex){errors.Add(Path.GetFileName(e.Baseline.Path)+": "+ex.Message);entries[i]=e with{Latest=null};}}Save();RefreshList();status.Text=$"Checked {count}/{entries.Count} at {DateTime.Now:t}. {errors.Count} unavailable; no baseline replaced.";if(errors.Count>0&&!auto.Checked)MessageBox.Show(string.Join("\n",errors),"Unavailable executables");});}catch(Exception ex){status.Text="Scan error: "+ex.Message;}}
    void Accept(){var e=Selected();if(e?.Latest==null){status.Text="Select an executable with a successful scan first.";return;}if(MessageBox.Show("Replace the saved baseline with the latest observation? Previous baseline evidence will be overwritten.","Accept baseline",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;entries[entries.IndexOf(e)]=new(e.Latest,null);Save();RefreshList();status.Text="Baseline accepted.";}
    void Remove(){var e=Selected();if(e==null)return;if(MessageBox.Show("Remove this saved baseline? The executable itself will not be deleted.","Remove tracking",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;entries.Remove(e);Save();RefreshList();status.Text="Tracking removed.";}
    void Export(){using var d=new SaveFileDialog{Filter="JSON report (*.json)|*.json",FileName="UpdateDetective-report.json"};if(d.ShowDialog(this)!=DialogResult.OK)return;File.WriteAllText(d.FileName,JsonSerializer.Serialize(new{GeneratedUtc=DateTime.UtcNow,Entries=entries.Select(e=>new{Result=Result(e),e.Baseline,e.Latest})},new JsonSerializerOptions{WriteIndented=true}));status.Text="Report exported locally.";}
}
