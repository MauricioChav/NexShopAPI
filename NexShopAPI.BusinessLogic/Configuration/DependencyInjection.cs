using Microsoft.Extensions.DependencyInjection;
using NexShopAPI.DataAccess.IOperations;
using NexShopAPI.DataAccess.Operations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.Configuration
{
    public static class DependencyInjection
    {
        public static IServiceCollection ImplementDBOperations(this IServiceCollection services) 
        {
            services.AddScoped<IClientOperation>(provider => provider.GetService<ClientOperations>());

            return services;
        }
    }
}
