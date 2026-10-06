using FileServerMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileServerMonitor.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<FileAuditEvent> FileAuditEvents { get; set; }
    }
}