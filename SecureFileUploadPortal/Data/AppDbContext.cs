using Microsoft.EntityFrameworkCore;

namespace SecureFileUploadPortal.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<FileRecord> Files => Set<FileRecord>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AppUser>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
            e.Property(u => u.Email).HasMaxLength(256).IsRequired();
            e.Property(u => u.DisplayName).HasMaxLength(100).IsRequired();
            e.Property(u => u.PasswordHash).IsRequired();
            e.Property(u => u.Role).HasMaxLength(20).IsRequired();
            e.Property(u => u.SecurityStamp).HasMaxLength(64).IsRequired();
        });

        b.Entity<FileRecord>(e =>
        {
            e.HasIndex(f => f.StorageKey).IsUnique();
            e.HasIndex(f => new { f.OwnerId, f.UploadedAtUtc });
            e.Property(f => f.StorageKey).HasMaxLength(200).IsRequired();
            e.Property(f => f.OriginalFileName).HasMaxLength(255).IsRequired();
            e.Property(f => f.ContentType).HasMaxLength(150).IsRequired();
            e.HasOne(f => f.Owner).WithMany(u => u.Files).HasForeignKey(f => f.OwnerId).OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<AuditLog>(e =>
        {
            e.HasIndex(a => a.TimestampUtc);
            e.HasIndex(a => new { a.Action, a.TimestampUtc });
            e.Property(a => a.UserEmail).HasMaxLength(256).IsRequired();
            e.Property(a => a.Action).HasMaxLength(50).IsRequired();
            e.Property(a => a.Target).HasMaxLength(500);
            e.Property(a => a.Details).HasMaxLength(1000);
            e.Property(a => a.IpAddress).HasMaxLength(45);
            // No FK: audit rows must survive independently of the user table.
        });
    }
}
