using Microsoft.EntityFrameworkCore;
using Todo_Api.Models;

namespace Todo_Api.Data
{
    public class AppDbContext:DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<TodoItem> TodoItems { get; set; }
    }
}
