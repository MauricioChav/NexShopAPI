using NexShopAPI.DataAccess.Models;
using System.ComponentModel.DataAnnotations;

namespace NexShopAPI.BusinessLogic.DTO.ClientDTO
{
    public class GetClientDto : BaseClientDto
    {
        public int Id { get; set; }
        public string? LastName { get; set; }
        public DateTime? Birthday { get; set; }
        public int? AddressId { get; set; }
    }
}
