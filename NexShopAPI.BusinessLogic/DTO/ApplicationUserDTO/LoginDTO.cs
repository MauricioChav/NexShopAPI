using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.DTO.ApplicationUserDTO
{
    public class LoginDTO
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        [StringLength(15, ErrorMessage = "The Password must have between {2} and {1} charaters"),
            MinLength(6)]
        public string Password { get; set; }
    }
}
