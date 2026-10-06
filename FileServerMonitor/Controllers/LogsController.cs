using Microsoft.AspNetCore.Mvc;
using FileServerMonitor.Data;
using Microsoft.EntityFrameworkCore;

namespace FileServerMonitor.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LogsController : ControllerBase
    {
        private readonly AppDbContext _db;

        public LogsController(AppDbContext db)
        {
            _db = db;
        }

        [HttpGet]
        public async Task<IActionResult> GetLogs()
        {
            var logs = await _db.FileAuditEvents
                .OrderByDescending(l => l.Timestamp)
                .ToListAsync();
            return Ok(logs);
        }
    }
}

