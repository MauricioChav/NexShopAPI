using System.ComponentModel.DataAnnotations;

namespace NexShopAPI.BusinessLogic.DTO.ClientDTO
{
    public class CreateClientDto : BaseClientDto
    {
        public string? LastName { get; set; }
        public DateTime? Birthday { get; set; }
    }
}
