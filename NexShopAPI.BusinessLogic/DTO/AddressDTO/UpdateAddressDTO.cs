using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.DTO.AddressDTO
{
    public class UpdateAddressDTO: BaseAddressDTO
    {
        public string? Country { get; set; }
        public string? State { get; set; }
        public string? City { get; set; }
        public string? Street { get; set; }
        public int? ZipCode { get; set; }
    }
}
