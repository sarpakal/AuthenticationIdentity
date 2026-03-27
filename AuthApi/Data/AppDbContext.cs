using AuthApi.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection.Emit;

namespace AuthApi.Data;

public class AppDbContext : IdentityDbContext<ApplicationUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<UserAuditLog> AuditLogs => Set<UserAuditLog>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(e =>
        {
            e.HasIndex(u => u.PhoneNumber).IsUnique();
            e.Property(u => u.PhoneNumber).HasMaxLength(20);
        });

        builder.Entity<UserAuditLog>(e =>
        {
            e.HasKey(a => a.Id);
            e.HasIndex(a => a.UserId);
            e.HasIndex(a => a.Timestamp);
            e.HasIndex(a => a.EventType);

            e.HasOne(a => a.User)
             .WithMany(u => u.AuditLogs)
             .HasForeignKey(a => a.UserId)
             .OnDelete(DeleteBehavior.Cascade);

            e.Property(a => a.EventType).HasMaxLength(50).IsRequired();
            e.Property(a => a.IpAddress).HasMaxLength(45);   // supports IPv6
            e.Property(a => a.UserAgent).HasMaxLength(512);
            e.Property(a => a.DeviceId).HasMaxLength(128);
        });
    }
}