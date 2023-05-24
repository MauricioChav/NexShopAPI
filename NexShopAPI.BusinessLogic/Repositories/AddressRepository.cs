using AutoMapper;
using NexShopAPI.BusinessLogic.DTO.AddressDTO;
using NexShopAPI.BusinessLogic.Exceptions;
using NexShopAPI.BusinessLogic.IRepositories;
using NexShopAPI.DataAccess;
using NexShopAPI.DataAccess.IOperations;
using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.Repositories
{
    public class AddressRepository: IAddressRepository
    {
        private readonly IAddressOperation _addressOperation;
        private readonly IClientOperation _clientOperations;
        private readonly IMapper _mapper;

        public AddressRepository(IAddressOperation addressOperation, IClientOperation clientOperations, IMapper mapper)
        {
            _addressOperation = addressOperation;
            _clientOperations = clientOperations;
            _mapper = mapper;
        }

        public async Task<GetAddressDTO> GetClientAddress(int client_id)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(client_id);

            if (clientExists)
            {
                //Verify if the client already has an address registered
                bool addressExists = await _addressOperation.AddressExistsbyClientIdAsync(client_id);

                if (addressExists)
                {
                    //Get address
                    GetAddressDTO address = _mapper.Map<GetAddressDTO>(await _addressOperation.GetClientAddressAsync(client_id));

                    //Add the client_id in the parameters
                    address.ClientId = client_id;

                    return address;
                }
                else
                {
                    throw new Exception("The client with the id '" + client_id + "' does not have an address registered.");
                }
                
            }
            else
            {
                throw new ClientNonExistentException(client_id);
            }

                
        }

        public async Task<GetAddressDTO> CreateClientAddress(CreateAddressDTO address)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(address.ClientId);

            if (clientExists)
            {
                //Verify if the client already has an address registered
                bool addressExists = await _addressOperation.AddressExistsbyClientIdAsync(address.ClientId);

                if (!addressExists)
                {
                    //Map the address DTO
                    var addressInfo = _mapper.Map<Address>(address);

                    //Create client address
                    var createdClient = _mapper.Map<GetAddressDTO>(await _addressOperation.InsertClientAddressAsync(address.ClientId, addressInfo));

                    //Add the client_id in the parameters
                    createdClient.ClientId = address.ClientId;

                    return createdClient;

                }
                else
                {
                    throw new Exception("The client with the id '" + address.ClientId + "' already has an address registered.");

                }
                
            }
            else
            {
                throw new ClientNonExistentException(address.ClientId);
            }
            
        }

        public async Task UpdateClientAddress(UpdateAddressDTO addressUpdate)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(addressUpdate.ClientId);
            
            if (clientExists)
            {
                //Verify if the client already has an address registered
                bool addressExists = await _addressOperation.AddressExistsbyClientIdAsync(addressUpdate.ClientId);
                if (addressExists)
                {
                    //Map the address DTO and update
                    var addressInfo = _mapper.Map<Address>(addressUpdate);
                    await _addressOperation.UpdateAddressAsync(addressUpdate.ClientId, addressInfo);
                }
                else
                {
                    throw new Exception("The client with the id '" + addressUpdate.ClientId + "' does not have an address registered.");
                }

                
            }
            else
            {
                throw new ClientNonExistentException(addressUpdate.ClientId);
            }
        }

        public async Task DeleteClientAddress(int client_id)
        {
            //Verify that the client exists
            bool clientExists = await _clientOperations.ClientExistsbyIdAsync(client_id);

            if (clientExists)
            {
                //Verify if the client already has an address registered
                bool addressExists = await _addressOperation.AddressExistsbyClientIdAsync(client_id);
                if (addressExists)
                {
                    await _addressOperation.DeleteClientAddressAsync(client_id);
                }
                else
                {
                    throw new Exception("The client with the id '" + client_id + "' did not have an address registered. No address to delete.");
                }

            }
            else
            {
                throw new ClientNonExistentException(client_id);
            }
        }
    }
}
