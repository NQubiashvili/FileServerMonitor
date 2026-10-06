using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FileServerMonitor.Models
{
    public class FileAuditEvent
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        [MaxLength(200)]
        public string Action { get; set; } = string.Empty;

        [MaxLength(4000)]
        public string? FullPath { get; set; }

        [MaxLength(4000)]
        public string? OldFullPath { get; set; }

        [MaxLength(50)]
        public string? IpAddress { get; set; }

        [MaxLength(255)]
        public string? PcName { get; set; }

        [Required]
        [MaxLength(255)]
        public string UserName { get; set; } = string.Empty;

        [MaxLength(255)]
        public string? Domain { get; set; }

        [MaxLength(255)]
        public string? ShareName { get; set; }

        [MaxLength(50)]
        public string? LogonId { get; set; }

        [MaxLength(50)]
        public string? AccessMask { get; set; }

        [Required]
        public DateTime Timestamp { get; set; }
    }
}
