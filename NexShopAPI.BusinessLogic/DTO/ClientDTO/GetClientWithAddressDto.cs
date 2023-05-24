using NexShopAPI.DataAccess.Models;
using System.ComponentModel.DataAnnotations;

namespace NexShopAPI.BusinessLogic.DTO.ClientDTO
{
    public class GetClientWithAddressDto : GetClientDto
    {
        public Address? Address { get; set; }
    }
}
