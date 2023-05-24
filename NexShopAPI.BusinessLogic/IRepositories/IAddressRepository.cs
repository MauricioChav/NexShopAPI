using NexShopAPI.BusinessLogic.DTO.AddressDTO;
using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.IRepositories
{
    public interface IAddressRepository
    {
        Task<GetAddressDTO> GetClientAddress(int client_id);
        Task<GetAddressDTO> CreateClientAddress(CreateAddressDTO address);
        Task UpdateClientAddress(UpdateAddressDTO addressUpdate);
        Task DeleteClientAddress(int client_id);
    }
}
