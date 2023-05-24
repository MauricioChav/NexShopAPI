using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.DTO.AddressDTO
{
    public abstract class BaseAddressDTO
    {
        [Required]
        public int ClientId { get; set; }
    }
}
