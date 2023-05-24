using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NexShopAPI.BusinessLogic.DTO.ApplicationUserDTO;
using NexShopAPI.BusinessLogic.IRepositories;
using NexShopAPI.DataAccess.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace NexShopAPI.BusinessLogic.Repositories
{
    public class AuthManager : IAuthManager
    {
        private readonly IMapper _mapper;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthManager(IMapper mapper, UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            this._mapper = mapper;
            this._userManager = userManager;
            this._configuration = configuration;
        }

        public async Task<AuthResponseDTO> Login(LoginDTO loginDTO)
        {
            var user = await _userManager.FindByEmailAsync(loginDTO.Email);
            bool isvalidUser = await _userManager.CheckPasswordAsync(user, loginDTO.Password);
            if (user == null || !isvalidUser)
            {
                return null;
            }

            var token = await GenerateToken(user);
            return new AuthResponseDTO
            {
                Token = token,
                UserId = user.Id
            };

        }

        public async Task<IEnumerable<IdentityError>> Register(ApplicationUserDTO userDTO)
        {
            var user = _mapper.Map<ApplicationUser>(userDTO);
            user.UserName = userDTO.Email;

            var result = await _userManager.CreateAsync(user, userDTO.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "User");
            }

            return result.Errors;
        }

        private async Task<string> GenerateToken(ApplicationUser user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]));

            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(x => new Claim(ClaimTypes.Role, x)).ToList();
            var userClaims = await _userManager.GetClaimsAsync(user);

            var claims = new List<Claim>
            {
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id),
            }
            .Union(userClaims).Union(roleClaims);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(Convert.ToInt32(_configuration["JwtSettings:DurationInMinutes"])),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
