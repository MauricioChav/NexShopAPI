using NexShopAPI.BusinessLogic.DTO.ClientDTO;

namespace NexShopAPI.BusinessLogic.IRepositories
{
    public interface IClientsRepository
    {
        Task<List<GetClientDto>> GetAllClients();
        Task<GetClientDto> GetClientById(int id);
        Task<GetClientDto> CreateClient(CreateClientDto client);
        Task UpdateClient(UpdateClientDTO clientUpdate);
        Task DeleteClient(int id);
        //Task<bool> ClientExistsbyId(int id);
    }
}
