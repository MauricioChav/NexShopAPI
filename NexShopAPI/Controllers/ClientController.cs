using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using NexShopAPI.BusinessLogic.DTO.ClientDTO;
using NexShopAPI.BusinessLogic.IRepositories;
using Microsoft.AspNetCore.Authorization;

namespace NexShopAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ClientController : ControllerBase
    {
        private readonly IClientsRepository _clientsRepository;

        public ClientController(IClientsRepository clientsRepository)
        {
            _clientsRepository = clientsRepository;
        }

        [HttpGet]
        [Route("GetAllClientsAsync")]
        public async Task<ActionResult<IEnumerable<GetClientDto>>> GetAllClientsAsync()
        {
            return await _clientsRepository.GetAllClients();

        }

        [HttpGet]
        [Route("GetClientAsync")]
        public async Task<ActionResult<GetClientDto>> GetClientAsync(int id)
        {
            if(id <= 0)
            {
                return BadRequest(new ProblemDetails 
                {
                    Title = "An error occured",
                    Status = 400,
                    Detail = "Invalid ClientId. The value must be equal or greater than 1." 
                });
            }

            var client = await _clientsRepository.GetClientById(id);
            return client;
            
        }

        [HttpPost]
        [Route("CreateClientAsync")]
        [Authorize]
        public async Task<ActionResult<GetClientDto>> CreateClientAsync(CreateClientDto clientInfo)
        {
            var newClient = await _clientsRepository.CreateClient(clientInfo);

            return newClient;

        }

        [HttpPatch]
        [Route("UpdateClientAsync")]
        [Authorize]
        public async Task<ActionResult> UpdateClientAsync(UpdateClientDTO updatedClient)
        {
            if(updatedClient.Id <= 0)
            {
                return BadRequest("Invalid ClientId. The value must be equal or greater than 1.");
            }

            await _clientsRepository.UpdateClient(updatedClient);
            return Ok("Client updated succesfully");

        }

        [HttpDelete]
        [Route("DeleteClientAsync")]
        [Authorize]
        public async Task<IActionResult> DeleteClientAsync(int id)
        {
            if (id <= 0)
            {
                return BadRequest("Invalid ClientId. The value must be equal or greater than 1.");
            }

            await _clientsRepository.DeleteClient(id);

            return Ok("The client with the id '" + id + "' was deleted succesfully");

        }

        /*[HttpGet]
        [Route("ClientExistsbyIdAsync")]
        public async Task<ActionResult<bool>> ClientExistsbyIdAsync(int id)
        {
            try
            {
                return await _clientsRepository.ClientExistsbyId(id);

            }
            catch (Exception ex)
            {
                throw new Exception("Error. Client exist check failed", ex);
            }

        }*/

    }
}
