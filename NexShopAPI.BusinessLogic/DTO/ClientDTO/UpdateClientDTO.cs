using System.ComponentModel.DataAnnotations;

namespace NexShopAPI.BusinessLogic.DTO.ClientDTO
{
    public class UpdateClientDTO : BaseClientDto
    {
        [Required]
        public int Id { get; set; }
        public new string? FirstName { get; set; }
        public new string? Email { get; set; }
        public string? LastName { get; set; }
        public DateTime? Birthday { get; set; }
    }
}
