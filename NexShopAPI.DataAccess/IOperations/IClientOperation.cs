using NexShopAPI.DataAccess;
using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.DataAccess.IOperations
{
    public interface IClientOperation
    {
        Task<List<Client>> GetAllClientsAsync();
        Task<Client> GetClientByIdAsync(int id);
        Task<Client> InsertClientAsync(Client client);
        Task UpdateClientAsync(Client client);
        Task DeleteClientByIdAsync(int id);
        Task<bool> ClientExistsbyIdAsync(int id);
    }
}
