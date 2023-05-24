using NexShopAPI.DataAccess.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NexShopAPI.DataAccess
{
    public class Client
    {
        [Key]
        public int Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTime? Birthday { get; set; }
        public string? Email { get; set; }
        public int? AddressId { get; set; }
        public Address? Address { get; set; }
        //Property of object, check annotations
        //[NotMapped]
        //public string FullName
        //{
        // get { return FirstName + " " + LastName; }
        //}

    }
}
