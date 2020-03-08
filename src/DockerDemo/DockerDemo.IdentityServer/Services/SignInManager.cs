using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using DockerDemo.IdentityServer.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace DockerDemo.IdentityServer.Services
{
    public class SignInManager: ISignInManager
    {
       private readonly SignInManager<IdentityUser> _signInManager;

		public SignInManager(SignInManager<IdentityUser> signInManager)
		{
			_signInManager = signInManager;
		}

		public IUserClaimsPrincipalFactory<IdentityUser> ClaimsFactory
		{
			get => _signInManager.ClaimsFactory;
			set => _signInManager.ClaimsFactory = value;
		}

		public HttpContext Context
		{
			get => _signInManager.Context;
			set => _signInManager.Context = value;
		}

		public ILogger Logger
		{
			get => _signInManager.Logger;
			set => _signInManager.Logger = value;
		}

		public IdentityOptions Options
		{
			get => _signInManager.Options;
			set => _signInManager.Options = value;
		}

		public UserManager<IdentityUser> UserManager
		{
			get => _signInManager.UserManager;
			set => _signInManager.UserManager = value;
		}

		public Task<bool> CanSignInAsync(IdentityUser user)
		{
			return _signInManager.CanSignInAsync(user);
		}

		public Task<SignInResult> CheckPasswordSignInAsync(IdentityUser user, string password, bool lockoutOnFailure)
		{
			return _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
		}

		public AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string redirectUrl, string userId = null)
		{
			return _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userId);
		}

		public Task<ClaimsPrincipal> CreateUserPrincipalAsync(IdentityUser user)
		{
			return _signInManager.CreateUserPrincipalAsync(user);
		}

		public Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent)
		{
			return _signInManager.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent);
		}

		public Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent,
															bool bypassTwoFactor)
		{
			return _signInManager.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor);
		}

		public Task ForgetTwoFactorClientAsync()
		{
			return _signInManager.ForgetTwoFactorClientAsync();
		}

		public Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync()
		{
			return _signInManager.GetExternalAuthenticationSchemesAsync();
		}

		public Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null)
		{
			return _signInManager.GetExternalLoginInfoAsync(expectedXsrf);
		}

		public Task<IdentityUser> GetTwoFactorAuthenticationUserAsync()
		{
			return _signInManager.GetTwoFactorAuthenticationUserAsync();
		}

		public bool IsSignedIn(ClaimsPrincipal principal)
		{
			return _signInManager.IsSignedIn(principal);
		}

		public Task<bool> IsTwoFactorClientRememberedAsync(IdentityUser user)
		{
			return _signInManager.IsTwoFactorClientRememberedAsync(user);
		}

		public Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
		{
			return _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
		}

		public Task<SignInResult> PasswordSignInAsync(IdentityUser user, string password, bool isPersistent, bool lockoutOnFailure)
		{
			return _signInManager.PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
		}

		public Task RefreshSignInAsync(IdentityUser user)
		{
			return _signInManager.RefreshSignInAsync(user);
		}

		public Task RememberTwoFactorClientAsync(IdentityUser user)
		{
			return _signInManager.RememberTwoFactorClientAsync(user);
		}

		public Task SignInAsync(IdentityUser user, AuthenticationProperties authenticationProperties, string authenticationMethod = null)
		{
			return _signInManager.SignInAsync(user, authenticationProperties, authenticationMethod);
		}

		public Task SignInAsync(IdentityUser user, bool isPersistent, string authenticationMethod = null)
		{
			return _signInManager.SignInAsync(user, isPersistent, authenticationMethod);
		}

		public Task SignInWithClaimsAsync(IdentityUser user, AuthenticationProperties authenticationProperties,
										IEnumerable<Claim> additionalClaims)
		{
			return _signInManager.SignInWithClaimsAsync(user, authenticationProperties, additionalClaims);
		}

		public Task SignInWithClaimsAsync(IdentityUser user, bool isPersistent, IEnumerable<Claim> additionalClaims)
		{
			return _signInManager.SignInWithClaimsAsync(user, isPersistent, additionalClaims);
		}

		public Task SignOutAsync()
		{
			return _signInManager.SignOutAsync();
		}

		public Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
		{
			return _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient);
		}

		public Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)
		{
			return _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
		}

		public Task<SignInResult> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberClient)
		{
			return _signInManager.TwoFactorSignInAsync(provider, code, isPersistent, rememberClient);
		}

		public Task<IdentityResult> UpdateExternalAuthenticationTokensAsync(ExternalLoginInfo externalLogin)
		{
			return _signInManager.UpdateExternalAuthenticationTokensAsync(externalLogin);
		}

		public Task<IdentityUser> ValidateSecurityStampAsync(ClaimsPrincipal principal)
		{
			return _signInManager.ValidateSecurityStampAsync(principal);
		}

		public Task<bool> ValidateSecurityStampAsync(IdentityUser user, string securityStamp)
		{
			return _signInManager.ValidateSecurityStampAsync(user, securityStamp);
		}

		public Task<IdentityUser> ValidateTwoFactorSecurityStampAsync(ClaimsPrincipal principal)
		{
			return _signInManager.ValidateTwoFactorSecurityStampAsync(principal);
		}
    }
}