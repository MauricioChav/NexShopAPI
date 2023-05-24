using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NexShopAPI.DataAccess.Configurations;
using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.DataAccess
{
    public class ApplicationDBContext: IdentityDbContext<ApplicationUser>
    {
        public ApplicationDBContext(DbContextOptions options) : base(options)
        {
            
        }
        //public DbSet<Client> Clients { get; set; }
        //public DbSet<Address> Addresses { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfiguration(new RoleConfiguration());
        }
    }
}
