using AutoMapper;
using NexShopAPI.BusinessLogic.DTO.ClientDTO;
using NexShopAPI.BusinessLogic.IRepositories;
using NexShopAPI.DataAccess.Operations;
using NexShopAPI.DataAccess;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NexShopAPI.DataAccess.IOperations;
using NexShopAPI.DataAccess.Models;
using NexShopAPI.BusinessLogic.Exceptions;

namespace NexShopAPI.BusinessLogic.Repositories
{
    public class ClientRepository : IClientsRepository
    {
        private readonly IClientOperation _clientOperations;
        private readonly IMapper _mapper;
        public ClientRepository(IClientOperation clientOperations, IMapper mapper)
        {
            _clientOperations = clientOperations;
            _mapper = mapper;
        }

        public async Task<List<GetClientDto>> GetAllClients()
        {
            List<GetClientDto> clientList = _mapper.Map<List<GetClientDto>>(await _clientOperations.GetAllClientsAsync());
            return clientList;
        }

        public async Task<GetClientDto> GetClientById(int id)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(id);

            if (clientExists)
            {
                Client clientInfo = await _clientOperations.GetClientByIdAsync(id);

                //Determine if the client has an existant address
                if(clientInfo.AddressId != null && clientInfo.AddressId != 0)
                {
                    return _mapper.Map<GetClientWithAddressDto>(clientInfo);
                }
                else
                {
                    return _mapper.Map<GetClientDto>(clientInfo); ;
                }
                
            }
            else
            {
                throw new ClientNonExistentException(id);
            }
        }

        public async Task<GetClientDto> CreateClient(CreateClientDto client)
        {
            var clientInfo = _mapper.Map<Client>(client);
            GetClientDto clientCreated = _mapper.Map<GetClientDto>(await _clientOperations.InsertClientAsync(clientInfo));
            return clientCreated;
        }

        public async Task UpdateClient(UpdateClientDTO clientUpdate)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(clientUpdate.Id);
            if (clientExists)
            {
                var clientInfo = _mapper.Map<Client>(clientUpdate);
                await _clientOperations.UpdateClientAsync(clientInfo);
            }
            else
            {
                throw new ClientNonExistentException(clientUpdate.Id);
            }
            
        }

        public async Task DeleteClient(int id)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(id);
            if (clientExists)
            {
                await _clientOperations.DeleteClientByIdAsync(id);
            }
            else
            {
                throw new ClientNonExistentException(id);
            }
            
        }

        /*public async Task<bool> ClientExistsbyId(int id)
        {
            return await _clientOperations.ClientExistsbyIdAsync(id);
        }*/
    }
}
