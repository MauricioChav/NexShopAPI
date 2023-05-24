using AutoMapper;
using NexShopAPI.BusinessLogic.DTO.AddressDTO;
using NexShopAPI.BusinessLogic.DTO.ApplicationUserDTO;
using NexShopAPI.BusinessLogic.DTO.ClientDTO;
using NexShopAPI.DataAccess;
using NexShopAPI.DataAccess.Models;

namespace NexShopAPI.Application.Functionality.Configuration
{
    public class AutoMapperConfig : Profile
    {
        public AutoMapperConfig()
        {
            CreateMap<Client, CreateClientDto>().ReverseMap();
            CreateMap<Client, GetClientDto>().ReverseMap();
            CreateMap<Client, GetClientWithAddressDto>().ReverseMap();
            CreateMap<Client, UpdateClientDTO>().ReverseMap();

            CreateMap<Address, CreateAddressDTO>().ReverseMap();
            CreateMap<Address, GetAddressDTO>().ReverseMap();
            CreateMap<Address, UpdateAddressDTO>().ReverseMap();

            CreateMap<ApplicationUserDTO, ApplicationUser>().ReverseMap();
        }
    }
}
