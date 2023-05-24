using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NexShopAPI.BusinessLogic.DTO.AddressDTO;
using NexShopAPI.BusinessLogic.IRepositories;
using NexShopAPI.BusinessLogic.Repositories;

namespace NexShopAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AddressController : ControllerBase
    {
        private readonly IAddressRepository _addressRepository;

        public AddressController(IAddressRepository addressRepository)
        {
            _addressRepository = addressRepository;
        }

        [HttpGet]
        [Route("GetClientAddressAsync")]
        public async Task<ActionResult<GetAddressDTO>> GetClientAddressAsync(int client_id)
        {
            //Parameter errors
            if (client_id <= 0)
            {
                return BadRequest("Invalid ClientId. The value must be equal or greater than 1.");
            }

            var address = await _addressRepository.GetClientAddress(client_id);
            return address;

        }

        [HttpPost]
        [Route("CreateClientAddressAsync")]
        [Authorize]
        public async Task<ActionResult<GetAddressDTO>> CreateClientAddressAsync(CreateAddressDTO addressInfo)
        {
            //Parameter errors
            if (addressInfo.ClientId <= 0)
            {
                return BadRequest("Invalid ClientId. The value must be equal or greater than 1.");

            }else if (addressInfo.ZipCode == 0)
            {
                return BadRequest("Invalid ZipCode");
            }

            var newAddress = await _addressRepository.CreateClientAddress(addressInfo);

            return newAddress;

        }

        [HttpPatch]
        [Route("UpdateClientAddressAsync")]
        [Authorize]
        public async Task<ActionResult> UpdateClientAddressAsync(UpdateAddressDTO addressInfo)
        {
            //Parameter errors
            if (addressInfo.ClientId <= 0)
            {
                return BadRequest("Invalid ClientId. The value must be equal or greater than 1.");

            }

            await _addressRepository.UpdateClientAddress(addressInfo);
            return Ok("Address updated succesfully");

        }

        [HttpDelete]
        [Route("DeleteClientAddressAsync")]
        [Authorize]
        public async Task<ActionResult> DeleteClientAddressAsync(int client_id)
        {
            //Parameter errors
            if (client_id <= 0)
            {
                return BadRequest("Invalid ClientId. The value must be equal or greater than 1.");

            }

            await _addressRepository.DeleteClientAddress(client_id);
            return Ok("Address deleted succesfully");

        }
    }
}
