using System;
using System.Linq;
using System.Threading.Tasks;
using DockerDemo.IdentityServer.Abstractions;
using DockerDemo.IdentityServer.Exceptions;
using DockerDemo.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;

namespace DockerDemo.IdentityServer.Services
{
    public class AuthService: IAuthService
    {
        private readonly ISignInManager _signInManager;

        private readonly IUserManager _userManager;

        public AuthService(ISignInManager signInManager, IUserManager userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public async Task<bool> AuthAsync(LoginViewModel model)
        {
            var user = await GetUserAsync(model.Email).ConfigureAwait(false);

            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user).ConfigureAwait(false);

            if (!isEmailConfirmed)
            {
                throw new EmailNotConfirmedException();
            }

            var result = await _signInManager
                .PasswordSignInAsync(user, model.Password, model.RememberMe, false)
                .ConfigureAwait(false);

            if (result.IsLockedOut)
            {
                throw new UserLockedOutException();
            }

            return result.Succeeded;
        }

        public async Task<bool> ResetPasswordAsync(string email, string token, string password)
        {
            var user = await GetUserAsync(email).ConfigureAwait(false);

            var result = await _userManager.ResetPasswordAsync(user, token, password).ConfigureAwait(false);

            if (!result.Succeeded)
            {
                throw new ResetPasswordException(string.Join(Environment.NewLine, result.Errors.Select(x => x.Description)));
            }

            return result.Succeeded;
        }

        public async Task<IdentityUser> GetUserAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email).ConfigureAwait(false);

            if (user == null)
            {
                throw new UserNotFoundException();
            }

            return user;
        }
    }
}