using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace API_JWT_TestOne.Models
{
    public class ApplicationDbContext: IdentityDbContext<ApplicationUsers>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options):base(options)
        {
            
     
        
        }




        public DbSet<ApplicationUsers> ApplicationUsers { get; set; } 
    }

}
