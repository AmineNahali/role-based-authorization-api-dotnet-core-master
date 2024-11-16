namespace WebApi.Helpers;

using Microsoft.EntityFrameworkCore;
using WebApi.Entities;

public class DataContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<Blacklist> Blacklisted { get; set; }

    private readonly IConfiguration Configuration;

    public DataContext(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        //options.UseInMemoryDatabase("TestDb");
        options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"), (sqlOptions) =>
            {
                sqlOptions.EnableRetryOnFailure();
            }
        );
    }
}