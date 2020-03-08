using System.Threading.Tasks;
using DockerDemo.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;

namespace DockerDemo.IdentityServer.Abstractions
{
    public interface IAuthService
    {
        Task<bool> AuthAsync(LoginViewModel model);

        Task<bool> ResetPasswordAsync(string email, string token, string password);

        Task<IdentityUser> GetUserAsync(string email);
    }
}