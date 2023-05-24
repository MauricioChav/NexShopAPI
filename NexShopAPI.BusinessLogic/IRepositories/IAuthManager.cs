using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using NexShopAPI.BusinessLogic.DTO.ApplicationUserDTO;

namespace NexShopAPI.BusinessLogic.IRepositories
{
    public interface IAuthManager
    {
        Task<IEnumerable<IdentityError>> Register(ApplicationUserDTO userDTO);
        Task<AuthResponseDTO> Login(LoginDTO loginDTO);
    }
}
