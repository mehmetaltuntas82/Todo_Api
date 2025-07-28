using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Todo_Api.Authentication.Role;
using Todo_Api.Authentication.SignUp;

namespace Todo_Api.Data
{
    public class IdentityDataContext : IdentityDbContext<AppUser, AppRole, int>
    {
        public IdentityDataContext(DbContextOptions<IdentityDataContext> options) : base(options)
        {

        }
    }
}
