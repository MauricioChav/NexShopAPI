using System.ComponentModel.DataAnnotations;

namespace NexShopAPI.BusinessLogic.DTO.ClientDTO
{
    public abstract class BaseClientDto
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string Email { get; set; }
    }
}
