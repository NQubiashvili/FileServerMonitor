using FileServerMonitor.Data;
using FileServerMonitor.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Xml;

namespace FileServerMonitor.Services
{
    public class FileSystemWatcherService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ConcurrentQueue<FileAuditEvent> _eventQueue = new();
        private readonly TimeSpan _dedupeWindow = TimeSpan.FromSeconds(1);
        private readonly ConcurrentDictionary<string, DateTime> _recentEvents = new();
        private readonly ConcurrentDictionary<string, string> _fileLastPath = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, List<FileAuditEvent>> _renameBuffer = new();
        private readonly ConcurrentDictionary<string, FileAuditEvent> _pendingHandles = new();

        // at class level
        private readonly ConcurrentDictionary<string, FileAuditEvent> _pendingDeletesBySession = new();
        private readonly ConcurrentDictionary<string, FileAuditEvent> _pendingCreatesBySession = new();
        private readonly ConcurrentDictionary<string, FileAuditEvent> _recentDeletesByUser = new(StringComparer.OrdinalIgnoreCase);


        private readonly ConcurrentDictionary<string, DateTime> _recentCreates = new(StringComparer.OrdinalIgnoreCase);
        private readonly TimeSpan _readAfterCreateWindow = TimeSpan.FromMilliseconds(800);



        private readonly ConcurrentDictionary<string, (string user, string domain, string pc, string? ip, DateTime time)>
            _sessionMap = new(StringComparer.OrdinalIgnoreCase);

        private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(10);
        private readonly TimeSpan _sessionTtl = TimeSpan.FromHours(4);

        private readonly string _shareRoot;
        private readonly string _uncShareName;

        public FileSystemWatcherService(IServiceProvider serviceProvider, IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;

            var watchedPath = configuration["WatchedPath"] ?? @"C:\share";
            if (watchedPath.StartsWith(@"\\"))
            {
                _uncShareName = watchedPath;
                _shareRoot = @"C:\share";
            }
            else
            {
                _shareRoot = watchedPath;
                _uncShareName = string.Empty;
            }
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Task.Run(() => StartWatcherLoop(stoppingToken), stoppingToken);
            Task.Run(() => ProcessQueue(stoppingToken), stoppingToken);
            Task.Run(() => SessionCleanupLoop(stoppingToken), stoppingToken);
            return Task.CompletedTask;
        }

        private void StartWatcherLoop(CancellationToken token)
        {
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=4624 or EventID=4656 or EventID=4663)]]");

            using var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += Watcher_EventRecordWritten;
            watcher.Enabled = true;

            Console.WriteLine("Security watcher started (4624, 4663). Running live...");

            try
            {
                while (!token.IsCancellationRequested)
                    Thread.Sleep(500);
            }
            finally
            {
                watcher.Enabled = false;
            }
        }

        private void Watcher_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;

            try
            {
                var xml = e.EventRecord.ToXml();
                var doc = new XmlDocument();
                doc.LoadXml(xml);

                var nsmgr = new XmlNamespaceManager(doc.NameTable);
                nsmgr.AddNamespace("ev", "http://schemas.microsoft.com/win/2004/08/events/event");

                string eventId = doc.SelectSingleNode("//ev:System/ev:EventID", nsmgr)?.InnerText ?? "";
                string correlationId = doc.SelectSingleNode("//ev:System/ev:Correlation/@ActivityID", nsmgr)?.InnerText ?? "";
                string logonGuid = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='LogonGuid']", nsmgr)?.InnerText ?? "";

                if (eventId == "4624")
                    Handle4624(doc, nsmgr, correlationId, logonGuid, e.EventRecord.TimeCreated);
                else if (eventId == "4663")
                    Handle4663(doc, nsmgr, correlationId, e.EventRecord.TimeCreated);
                else if (eventId == "4656")
                    Handle4656(doc, nsmgr, correlationId, e.EventRecord.TimeCreated);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Event parse error: {ex.Message}");
            }
        }

        private void Handle4624(XmlDocument doc, XmlNamespaceManager nsmgr, string correlationId, string logonGuid, DateTime? timeCreated)
        {
            string user = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='TargetUserName']", nsmgr)?.InnerText ?? "";
            string domain = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='TargetDomainName']", nsmgr)?.InnerText ?? "";
            string pc = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='WorkstationName']", nsmgr)?.InnerText ?? "";
            string ip = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='IpAddress']", nsmgr)?.InnerText ?? "";
            string targetLogonId = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='TargetLogonId']", nsmgr)?.InnerText ?? logonGuid;


            // Skip system accounts
            if (string.IsNullOrEmpty(user) || user.EndsWith("$", StringComparison.OrdinalIgnoreCase)
                || string.Equals(user, "SYSTEM", StringComparison.OrdinalIgnoreCase)
                || string.Equals(user, "Administrator", StringComparison.OrdinalIgnoreCase))
                return;

            _sessionMap[targetLogonId] = (user, domain, pc, string.IsNullOrWhiteSpace(ip) ? null : ip, DateTime.UtcNow);

            _eventQueue.Enqueue(new FileAuditEvent
            {
                Action = "Logon",
                FullPath = null,
                OldFullPath = null,
                Timestamp = timeCreated ?? DateTime.UtcNow,
                UserName = string.IsNullOrEmpty(user) ? "UNKNOWN" : user,
                PcName = pc,
                IpAddress = string.IsNullOrWhiteSpace(ip) ? null : ip,
                Domain = domain,
            });
        }

        private void Handle4656(XmlDocument doc, XmlNamespaceManager nsmgr, string correlationId, DateTime? timeCreated)
        {
            string objectName = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='ObjectName']", nsmgr)?.InnerText ?? "";
            string accessMask = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='AccessMask']", nsmgr)?.InnerText ?? "";
            string subjectUser = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='SubjectUserName']", nsmgr)?.InnerText ?? "";
            string subjectDomain = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='SubjectDomainName']", nsmgr)?.InnerText ?? "";
            string targetLogonId = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='SubjectLogonId']", nsmgr)?.InnerText ?? "";
            DateTime now = timeCreated ?? DateTime.UtcNow;

            if (string.IsNullOrWhiteSpace(objectName))
                return;
            if (string.IsNullOrEmpty(subjectUser) || subjectUser.EndsWith("$", StringComparison.OrdinalIgnoreCase)
                || subjectUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
                || subjectUser.Equals("Administrator", StringComparison.OrdinalIgnoreCase))
                return;

            string? action = ParseAccessMask(accessMask, objectName);
            if (string.IsNullOrEmpty(action))
                return;

            string pc = "Unknown";
            string? ip = null;
            if (_sessionMap.TryGetValue(targetLogonId, out var session))
            {
                pc = string.IsNullOrWhiteSpace(session.pc) ? "Unknown" : session.pc;
                ip = session.ip;
            }

            // 🔹 Folder creation detection (4656 logs handle creation on directories)
            if ((action.Contains("WriteData", StringComparison.OrdinalIgnoreCase) ||
                 action.Contains("Create", StringComparison.OrdinalIgnoreCase)) &&
                Directory.Exists(Path.GetDirectoryName(objectName) ?? string.Empty))
            {
                if (!File.Exists(objectName))
                {
                    _eventQueue.Enqueue(new FileAuditEvent
                    {
                        Action = "CreateFolder",
                        FullPath = objectName,
                        Timestamp = now,
                        UserName = subjectUser,
                        PcName = pc,
                        IpAddress = ip,
                        Domain = subjectDomain
                    });
                }
                return;
            }

            // 🔹 Delete detection (early handle open for delete)
            if (action.Contains("Delete", StringComparison.OrdinalIgnoreCase))
            {
                string sessionKey = $"{subjectUser}|{targetLogonId}";
                var evt = new FileAuditEvent
                {
                    Action = "Delete",
                    FullPath = objectName,
                    Timestamp = now,
                    UserName = subjectUser,
                    PcName = pc,
                    IpAddress = ip,
                    Domain = subjectDomain
                };

                _pendingDeletesBySession[sessionKey] = evt;
                _recentDeletesByUser[subjectUser] = evt;
            }
        }


        private void Handle4663(XmlDocument doc, XmlNamespaceManager nsmgr, string correlationId, DateTime? timeCreated)
        {
            string objectName = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='ObjectName']", nsmgr)?.InnerText ?? "";
            string accessMask = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='AccessMask']", nsmgr)?.InnerText ?? "";
            string subjectUser = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='SubjectUserName']", nsmgr)?.InnerText ?? "";
            string subjectDomain = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='SubjectDomainName']", nsmgr)?.InnerText ?? "";
            string targetLogonId = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='SubjectLogonId']", nsmgr)?.InnerText ?? "";
            string handleId = doc.SelectSingleNode("//ev:EventData/ev:Data[@Name='HandleId']", nsmgr)?.InnerText ?? "";
            DateTime now = timeCreated ?? DateTime.UtcNow;

            if (string.IsNullOrWhiteSpace(objectName))
                return;

            if (string.IsNullOrEmpty(subjectUser) || subjectUser.EndsWith("$", StringComparison.OrdinalIgnoreCase)
                || subjectUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase)
                || subjectUser.Equals("Administrator", StringComparison.OrdinalIgnoreCase))
                return;

            string? action = ParseAccessMask(accessMask, objectName);
            if (string.IsNullOrEmpty(action))
                return;

            // session key (per-user / per-logon)
            string sessionKey = $"{subjectUser}|{targetLogonId}";

            // --- session info ---
            string pc = "Unknown";
            string? ip = null;
            if (_sessionMap.TryGetValue(targetLogonId, out var session))
            {
                pc = string.IsNullOrWhiteSpace(session.pc) ? "Unknown" : session.pc;
                ip = session.ip;
            }

            // --- dedupe ---
            string dedupeKey = $"{objectName}|{subjectUser}|{action}";
            if (_recentEvents.TryGetValue(dedupeKey, out var lastTime) && (DateTime.UtcNow - lastTime) < _dedupeWindow)
                return;
            _recentEvents[dedupeKey] = DateTime.UtcNow;

            var evt = new FileAuditEvent
            {
                Action = action,
                FullPath = objectName,
                Timestamp = now,
                UserName = subjectUser,
                PcName = pc,
                IpAddress = ip,
                Domain = subjectDomain,
                AccessMask = accessMask
            };

            const int deleteDelayMs = 500;   // delay before confirming delete (lets rename/move arrive)
            const int renameWindowMs = 2000;  // max time between delete and new name

            // ------------------
            // 1) DELETE: store pendingDelete (do not log immediately)
            // ------------------
            if (action.Contains("Delete", StringComparison.OrdinalIgnoreCase))
            {

                _recentDeletesByUser[subjectUser] = evt;


                // store pending delete (by session)
                _pendingDeletesBySession[sessionKey] = evt;

                // also keep handle-based pending (optional)
                _pendingHandles[handleId] = evt;

                // schedule "confirm delete" after delay unless matched by a rename/move
                _ = Task.Run(async () =>
                {
                    await Task.Delay(deleteDelayMs);

                    // If still present (no rename/move matched), log delete
                    if (_pendingDeletesBySession.TryRemove(sessionKey, out var pendingDelete))
                    {
                        // also remove handle-based pending if present
                        _pendingHandles.TryRemove(handleId, out _);

                        _eventQueue.Enqueue(new FileAuditEvent
                        {
                            Action = "Delete",
                            FullPath = pendingDelete.FullPath,
                            Timestamp = pendingDelete.Timestamp,
                            UserName = pendingDelete.UserName,
                            PcName = pendingDelete.PcName,
                            IpAddress = pendingDelete.IpAddress,
                            Domain = pendingDelete.Domain
                        });
                    }
                });

                return; // don't log delete now
            }

            // -----------------------------
            // 2) Handle Create/Write (for possible Rename/Move)
            // -----------------------------
            if (action.Contains("WriteData", StringComparison.OrdinalIgnoreCase) || action.Contains("Append", StringComparison.OrdinalIgnoreCase))
            {
                // ignore folder-level writes
                if (Directory.Exists(objectName)) return;

                // --- Ignore temporary and system-generated files ---
                string fileName = Path.GetFileName(objectName);
                if (fileName.StartsWith("~$", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                    return;


                FileAuditEvent? oldDelete = null;
                // if a pending delete exists for this session → rename/move detection
                if (_pendingDeletesBySession.TryRemove(sessionKey, out var pendingDelete))
                {
                    _pendingCreatesBySession.TryRemove(sessionKey, out _);
                    _pendingHandles.TryRemove(handleId, out _);

                    double diffMs = (now - pendingDelete.Timestamp).TotalMilliseconds;
                    if (diffMs <= renameWindowMs)
                    {
                        // ✅ Handle Recycle Bin as true Delete
                        if (objectName.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase))
                        {
                            _eventQueue.Enqueue(new FileAuditEvent
                            {
                                Action = "Delete",
                                FullPath = pendingDelete.OldFullPath,
                                OldFullPath = null,
                                Timestamp = now,
                                UserName = subjectUser,
                                PcName = pc,
                                IpAddress = ip,
                                Domain = subjectDomain
                            });

                            // cleanup references
                            _fileLastPath.TryRemove(pendingDelete.FullPath, out _);
                            return;
                        }

                        // ✅ Normal Move/Rename
                        bool sameDir = string.Equals(
                            Path.GetDirectoryName(pendingDelete.FullPath) ?? "",
                            Path.GetDirectoryName(objectName) ?? "",
                            StringComparison.OrdinalIgnoreCase);

                        _eventQueue.Enqueue(new FileAuditEvent
                        {
                            Action = sameDir ? "Rename" : "Move",
                            OldFullPath = pendingDelete.FullPath,
                            FullPath = objectName,
                            Timestamp = now,
                            UserName = subjectUser,
                            PcName = pc,
                            IpAddress = ip,
                            Domain = subjectDomain
                        });

                        _fileLastPath[objectName] = objectName;
                        _fileLastPath.TryRemove(pendingDelete.FullPath, out _);
                        return;
                    }
                }


                // Normal Create/Modify
                bool isNew = !_fileLastPath.ContainsKey(objectName);
                _eventQueue.Enqueue(new FileAuditEvent
                {
                    Action = isNew ? "Create" : "Write (Modify)",
                    FullPath = objectName,
                    Timestamp = now,
                    UserName = subjectUser,
                    PcName = pc,
                    IpAddress = ip,
                    Domain = subjectDomain
                });
                _fileLastPath[objectName] = objectName;
                if (isNew) _recentCreates[objectName] = DateTime.UtcNow;
                return;
            }

            // ------------------
            // 3) READATTRIBUTES: usually appears when a file/folder is accessed
            // ------------------
            if (action.Contains("ReadAttributes", StringComparison.OrdinalIgnoreCase))
            {
                // ignore folder-level reads — these flood logs
                if (Directory.Exists(objectName) || objectName.Equals(_shareRoot, StringComparison.OrdinalIgnoreCase))
                    return;

                // ------------------------
                // SUPPRESS READS IMMEDIATELY AFTER CREATE
                // ------------------------
                if (_recentCreates.TryGetValue(objectName, out var createdTime))
                {
                    if ((now - createdTime) < _readAfterCreateWindow)
                    {
                        // remove from recent creates and skip logging
                        _recentCreates.TryRemove(objectName, out _);
                        return;
                    }

                    _recentCreates.TryRemove(objectName, out _);
                }

                // ignore temporary or repeat reads within dedupe window
                string dedupeReadKey = $"READ|{subjectUser}|{objectName}";
                if (_recentEvents.TryGetValue(dedupeReadKey, out var lastRead) && (DateTime.UtcNow - lastRead) < _dedupeWindow)
                    return;
                _recentEvents[dedupeReadKey] = DateTime.UtcNow;

                // if a pending delete exists for this session → rename/move detection
                if (_pendingDeletesBySession.TryRemove(sessionKey, out var pendingDelete))
                {
                    _pendingCreatesBySession.TryRemove(sessionKey, out _);
                    _pendingHandles.TryRemove(handleId, out _);

                    double diffMs = (now - pendingDelete.Timestamp).TotalMilliseconds;
                    if (diffMs <= renameWindowMs)
                    {
                        bool sameDir = string.Equals(
                            Path.GetDirectoryName(pendingDelete.FullPath) ?? "",
                            Path.GetDirectoryName(objectName) ?? "",
                            StringComparison.OrdinalIgnoreCase);

                        _eventQueue.Enqueue(new FileAuditEvent
                        {
                            Action = sameDir ? "Rename" : "Move",
                            OldFullPath = pendingDelete.FullPath,
                            FullPath = objectName,
                            Timestamp = now,
                            UserName = subjectUser,
                            PcName = pc,
                            IpAddress = ip,
                            Domain = subjectDomain
                        });

                        _fileLastPath[objectName] = objectName;
                        _fileLastPath.TryRemove(pendingDelete.FullPath, out _);
                        return;
                    }
                }


                // skip pure folder metadata reads and drive-level reads
                if (string.Equals(Path.GetDirectoryName(objectName), _shareRoot, StringComparison.OrdinalIgnoreCase))
                    return;

                // Only log a "Read (Open)" once per file access
                _eventQueue.Enqueue(new FileAuditEvent
                {
                    Action = "Read (Open)",
                    FullPath = objectName,
                    Timestamp = now,
                    UserName = subjectUser,
                    PcName = pc,
                    IpAddress = ip,
                    Domain = subjectDomain
                });
                _fileLastPath[objectName] = objectName;
                return;
            }

            // ------------------
            // Fallback: if some other meaningful action arrived, log it
            // ------------------
            _eventQueue.Enqueue(evt);
        }






        //private string? ParseAccessMask(string mask) => mask switch
        //{
        //    "0x1" => "Read (Open)",
        //    "0x2" => "Create",
        //    "0x4" => "Append (Modify)",
        //    "0x10000" => "Delete",
        //    "0x100000" => "Rename",
        //    // "0x20000" => "Close Handle", // skip it
        //    _ => null
        //};

        private string? ParseAccessMask(string maskHex, string objectName = "")
        {
            if (!int.TryParse(maskHex.Replace("0x", ""),
                System.Globalization.NumberStyles.HexNumber,
                null, out int mask))
                return null;

            var results = new List<string>();

            // File/Dir rights
            if ((mask & 0x1) != 0) results.Add("ReadData/ListDirectory");
            if ((mask & 0x2) != 0) results.Add("WriteData/Create");
            if ((mask & 0x4) != 0) results.Add("ცვლილება");
            if ((mask & 0x8) != 0) results.Add("ReadEA");
            if ((mask & 0x10) != 0) results.Add("WriteEA");
            if ((mask & 0x20) != 0) results.Add("Execute/Traverse");
            if ((mask & 0x40) != 0) results.Add("DeleteChild");
            if ((mask & 0x80) != 0) results.Add("ReadAttributes");
            if ((mask & 0x100) != 0) results.Add("WriteAttributes");

            // Standard rights
            if ((mask & 0x10000) != 0) results.Add("Delete");
            if ((mask & 0x20000) != 0) results.Add("წაკითხვა");

            // Generic rights
            if ((mask & 0x10000000) != 0) results.Add("GenericAll (Full Control)");
            if ((mask & 0x20000000) != 0) results.Add("GenericExecute");
            if ((mask & 0x40000000) != 0) results.Add("GenericWrite");
            if ((mask & 0x80000000) != 0) results.Add("GenericRead");


            // 🎯 FILTER OUT BROWSING NOISE
            var meaningful = results.Where(r =>
                r.Contains("ReadAttributes") ||
                r.Contains("WriteData/Create") ||
                r.Contains("Write") ||
                r.Contains("Delete") ||
                r.Contains("Append") ||
                r.Contains("GenericAll") ||
                r.Contains("GenericWrite") ||
                // Special: log EXE opens
                (r.Contains("Execute") && objectName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            ).ToList();



            if (meaningful.Count == 0)
                return null;

            return string.Join(", ", meaningful);
        }



        private async Task ProcessQueue(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                while (_eventQueue.TryDequeue(out var log))
                {
                    try
                    {
                        using var scope = _serviceProvider.CreateScope();
                        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                        db.FileAuditEvents.Add(log);
                        await db.SaveChangesAsync(token);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"DB error: {ex.Message}");
                    }
                }

                await Task.Delay(500, token);
            }
        }

        private async Task SessionCleanupLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var cutoff = DateTime.UtcNow - _sessionTtl;
                    var keysToRemove = _sessionMap.Where(kvp => kvp.Value.time < cutoff).Select(kvp => kvp.Key).ToList();
                    foreach (var k in keysToRemove)
                        _sessionMap.TryRemove(k, out _);
                }
                catch { }

                await Task.Delay(_cleanupInterval, token);
            }
        }
    }
}

