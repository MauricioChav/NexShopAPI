using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.DataAccess.IOperations
{
    public interface IAddressOperation
    {
        Task<Address> GetClientAddressAsync(int client_id);
        Task<Address> InsertClientAddressAsync(int client_id, Address address);
        Task UpdateAddressAsync(int client_id, Address address);
        Task DeleteClientAddressAsync(int client_id);
        Task<bool> AddressExistsbyClientIdAsync(int client_id);
    }
}
