using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using DockerDemo.IdentityServer.Abstractions;
using Microsoft.AspNetCore.Identity;

namespace DockerDemo.IdentityServer.Services
{
    public class UserManager: IUserManager
    {
		private readonly UserManager<IdentityUser> _manager;

		public UserManager(UserManager<IdentityUser> manager)
		{
			_manager = manager;
		}

		/// <inheritdoc />
		public bool SupportsUserSecurityStamp => _manager.SupportsUserSecurityStamp;

		public Task<IdentityResult> AccessFailedAsync(IdentityUser user)
		{
			return _manager.AccessFailedAsync(user);
		}

		public Task<IdentityResult> AddClaimAsync(IdentityUser user, Claim claim)
		{
			return _manager.AddClaimAsync(user, claim);
		}

		public Task<IdentityResult> AddClaimsAsync(IdentityUser user, IEnumerable<Claim> claims)
		{
			return _manager.AddClaimsAsync(user, claims);
		}

		public Task<IdentityResult> AddLoginAsync(IdentityUser user, UserLoginInfo login)
		{
			return _manager.AddLoginAsync(user, login);
		}

		public Task<IdentityResult> AddPasswordAsync(IdentityUser user, string password)
		{
			return _manager.AddPasswordAsync(user, password);
		}

		public Task<IdentityResult> AddToRoleAsync(IdentityUser user, string role)
		{
			return _manager.AddToRoleAsync(user, role);
		}

		public Task<IdentityResult> AddToRolesAsync(IdentityUser user, IEnumerable<string> roles)
		{
			return _manager.AddToRolesAsync(user, roles);
		}

		public Task<IdentityResult> ChangeEmailAsync(IdentityUser user, string newEmail, string token)
		{
			return _manager.ChangeEmailAsync(user, newEmail, token);
		}

		public Task<IdentityResult> ChangePasswordAsync(IdentityUser user, string currentPassword, string newPassword)
		{
			return _manager.ChangePasswordAsync(user, currentPassword, newPassword);
		}

		public Task<IdentityResult> ChangePhoneNumberAsync(IdentityUser user, string phoneNumber, string token)
		{
			return _manager.ChangePhoneNumberAsync(user, phoneNumber, token);
		}

		public Task<bool> CheckPasswordAsync(IdentityUser user, string password)
		{
			return _manager.CheckPasswordAsync(user, password);
		}

		public Task<IdentityResult> ConfirmEmailAsync(IdentityUser user, string token)
		{
			return _manager.ConfirmEmailAsync(user, token);
		}

		public Task<int> CountRecoveryCodesAsync(IdentityUser user)
		{
			return _manager.CountRecoveryCodesAsync(user);
		}

		public Task<IdentityResult> CreateAsync(IdentityUser user)
		{
			return _manager.CreateAsync(user);
		}

		public Task<IdentityResult> CreateAsync(IdentityUser user, string password)
		{
			return _manager.CreateAsync(user, password);
		}

		public Task<byte[]> CreateSecurityTokenAsync(IdentityUser user)
		{
			return _manager.CreateSecurityTokenAsync(user);
		}

		public Task<IdentityResult> DeleteAsync(IdentityUser user)
		{
			return _manager.DeleteAsync(user);
		}

		public void Dispose()
		{
			_manager.Dispose();
		}

		public Task<IdentityUser> FindByEmailAsync(string email)
		{
			return _manager.FindByEmailAsync(email);
		}

		public Task<IdentityUser> FindByIdAsync(string userId)
		{
			return _manager.FindByIdAsync(userId);
		}

		public Task<IdentityUser> FindByLoginAsync(string loginProvider, string providerKey)
		{
			return _manager.FindByLoginAsync(loginProvider, providerKey);
		}

		public Task<IdentityUser> FindByNameAsync(string userName)
		{
			return _manager.FindByNameAsync(userName);
		}

		public Task<string> GenerateChangeEmailTokenAsync(IdentityUser user, string newEmail)
		{
			return _manager.GenerateChangeEmailTokenAsync(user, newEmail);
		}

		public Task<string> GenerateChangePhoneNumberTokenAsync(IdentityUser user, string phoneNumber)
		{
			return _manager.GenerateChangePhoneNumberTokenAsync(user, phoneNumber);
		}

		public Task<string> GenerateConcurrencyStampAsync(IdentityUser user)
		{
			return _manager.GenerateConcurrencyStampAsync(user);
		}

		public Task<string> GenerateEmailConfirmationTokenAsync(IdentityUser user)
		{
			return _manager.GenerateEmailConfirmationTokenAsync(user);
		}

		public string GenerateNewAuthenticatorKey()
		{
			return _manager.GenerateNewAuthenticatorKey();
		}

		public Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(IdentityUser user, int number)
		{
			return _manager.GenerateNewTwoFactorRecoveryCodesAsync(user, number);
		}

		public Task<string> GeneratePasswordResetTokenAsync(IdentityUser user)
		{
			return _manager.GeneratePasswordResetTokenAsync(user);
		}

		public Task<string> GenerateTwoFactorTokenAsync(IdentityUser user, string tokenProvider)
		{
			return _manager.GenerateTwoFactorTokenAsync(user, tokenProvider);
		}

		public Task<string> GenerateUserTokenAsync(IdentityUser user, string tokenProvider, string purpose)
		{
			return _manager.GenerateUserTokenAsync(user, tokenProvider, purpose);
		}

		public Task<int> GetAccessFailedCountAsync(IdentityUser user)
		{
			return _manager.GetAccessFailedCountAsync(user);
		}

		public Task<string> GetAuthenticationTokenAsync(IdentityUser user, string loginProvider, string tokenName)
		{
			return _manager.GetAuthenticationTokenAsync(user, loginProvider, tokenName);
		}

		public Task<string> GetAuthenticatorKeyAsync(IdentityUser user)
		{
			return _manager.GetAuthenticatorKeyAsync(user);
		}

		public Task<IList<Claim>> GetClaimsAsync(IdentityUser user)
		{
			return _manager.GetClaimsAsync(user);
		}

		public Task<string> GetEmailAsync(IdentityUser user)
		{
			return _manager.GetEmailAsync(user);
		}

		public Task<bool> GetLockoutEnabledAsync(IdentityUser user)
		{
			return _manager.GetLockoutEnabledAsync(user);
		}

		public Task<DateTimeOffset?> GetLockoutEndDateAsync(IdentityUser user)
		{
			return _manager.GetLockoutEndDateAsync(user);
		}

		public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user)
		{
			return _manager.GetLoginsAsync(user);
		}

		public Task<string> GetPhoneNumberAsync(IdentityUser user)
		{
			return _manager.GetPhoneNumberAsync(user);
		}

		public Task<IList<string>> GetRolesAsync(IdentityUser user)
		{
			return _manager.GetRolesAsync(user);
		}

		public Task<string> GetSecurityStampAsync(IdentityUser user)
		{
			return _manager.GetSecurityStampAsync(user);
		}

		public Task<bool> GetTwoFactorEnabledAsync(IdentityUser user)
		{
			return _manager.GetTwoFactorEnabledAsync(user);
		}

		public Task<IdentityUser> GetUserAsync(ClaimsPrincipal principal)
		{
			return _manager.GetUserAsync(principal);
		}

		public string GetUserId(ClaimsPrincipal principal)
		{
			return _manager.GetUserId(principal);
		}

		public Task<string> GetUserIdAsync(IdentityUser user)
		{
			return _manager.GetUserIdAsync(user);
		}

		public string GetUserName(ClaimsPrincipal principal)
		{
			return _manager.GetUserName(principal);
		}

		public Task<string> GetUserNameAsync(IdentityUser user)
		{
			return _manager.GetUserNameAsync(user);
		}

		public Task<IList<IdentityUser>> GetUsersForClaimAsync(Claim claim)
		{
			return _manager.GetUsersForClaimAsync(claim);
		}

		public Task<IList<IdentityUser>> GetUsersInRoleAsync(string roleName)
		{
			return _manager.GetUsersInRoleAsync(roleName);
		}

		public Task<IList<string>> GetValidTwoFactorProvidersAsync(IdentityUser user)
		{
			return _manager.GetValidTwoFactorProvidersAsync(user);
		}

		public Task<bool> HasPasswordAsync(IdentityUser user)
		{
			return _manager.HasPasswordAsync(user);
		}

		public Task<bool> IsEmailConfirmedAsync(IdentityUser user)
		{
			return _manager.IsEmailConfirmedAsync(user);
		}

		public Task<bool> IsInRoleAsync(IdentityUser user, string role)
		{
			return _manager.IsInRoleAsync(user, role);
		}

		public Task<bool> IsLockedOutAsync(IdentityUser user)
		{
			return _manager.IsLockedOutAsync(user);
		}

		public Task<bool> IsPhoneNumberConfirmedAsync(IdentityUser user)
		{
			return _manager.IsPhoneNumberConfirmedAsync(user);
		}

		public string NormalizeEmail(string email)
		{
			return _manager.NormalizeEmail(email);
		}

		public string NormalizeName(string name)
		{
			return _manager.NormalizeName(name);
		}

		public Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(IdentityUser user, string code)
		{
			return _manager.RedeemTwoFactorRecoveryCodeAsync(user, code);
		}

		public void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<IdentityUser> provider)
		{
			_manager.RegisterTokenProvider(providerName, provider);
		}

		public Task<IdentityResult> RemoveAuthenticationTokenAsync(IdentityUser user, string loginProvider, string tokenName)
		{
			return _manager.RemoveAuthenticationTokenAsync(user, loginProvider, tokenName);
		}

		public Task<IdentityResult> RemoveClaimAsync(IdentityUser user, Claim claim)
		{
			return _manager.RemoveClaimAsync(user, claim);
		}

		public Task<IdentityResult> RemoveClaimsAsync(IdentityUser user, IEnumerable<Claim> claims)
		{
			return _manager.RemoveClaimsAsync(user, claims);
		}

		public Task<IdentityResult> RemoveFromRoleAsync(IdentityUser user, string role)
		{
			return _manager.RemoveFromRoleAsync(user, role);
		}

		public Task<IdentityResult> RemoveFromRolesAsync(IdentityUser user, IEnumerable<string> roles)
		{
			return _manager.RemoveFromRolesAsync(user, roles);
		}

		public Task<IdentityResult> RemoveLoginAsync(IdentityUser user, string loginProvider, string providerKey)
		{
			return _manager.RemoveLoginAsync(user, loginProvider, providerKey);
		}

		public Task<IdentityResult> RemovePasswordAsync(IdentityUser user)
		{
			return _manager.RemovePasswordAsync(user);
		}

		public Task<IdentityResult> ReplaceClaimAsync(IdentityUser user, Claim claim, Claim newClaim)
		{
			return _manager.ReplaceClaimAsync(user, claim, newClaim);
		}

		public Task<IdentityResult> ResetAccessFailedCountAsync(IdentityUser user)
		{
			return _manager.ResetAccessFailedCountAsync(user);
		}

		public Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user)
		{
			return _manager.ResetAuthenticatorKeyAsync(user);
		}

		public Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword)
		{
			return _manager.ResetPasswordAsync(user, token, newPassword);
		}

		public Task<IdentityResult> SetAuthenticationTokenAsync(IdentityUser user, string loginProvider, string tokenName, string tokenValue)
		{
			return _manager.SetAuthenticationTokenAsync(user, loginProvider, tokenName, tokenValue);
		}

		public Task<IdentityResult> SetEmailAsync(IdentityUser user, string email)
		{
			return _manager.SetEmailAsync(user, email);
		}

		public Task<IdentityResult> SetLockoutEnabledAsync(IdentityUser user, bool enabled)
		{
			return _manager.SetLockoutEnabledAsync(user, enabled);
		}

		public Task<IdentityResult> SetLockoutEndDateAsync(IdentityUser user, DateTimeOffset? lockoutEnd)
		{
			return _manager.SetLockoutEndDateAsync(user, lockoutEnd);
		}

		public Task<IdentityResult> SetPhoneNumberAsync(IdentityUser user, string phoneNumber)
		{
			return _manager.SetPhoneNumberAsync(user, phoneNumber);
		}

		public Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled)
		{
			return _manager.SetTwoFactorEnabledAsync(user, enabled);
		}

		public Task<IdentityResult> SetUserNameAsync(IdentityUser user, string userName)
		{
			return _manager.SetUserNameAsync(user, userName);
		}

		public Task<IdentityResult> UpdateAsync(IdentityUser user)
		{
			return _manager.UpdateAsync(user);
		}

		public Task UpdateNormalizedEmailAsync(IdentityUser user)
		{
			return _manager.UpdateNormalizedEmailAsync(user);
		}

		public Task UpdateNormalizedUserNameAsync(IdentityUser user)
		{
			return _manager.UpdateNormalizedUserNameAsync(user);
		}

		public Task<IdentityResult> UpdateSecurityStampAsync(IdentityUser user)
		{
			return _manager.UpdateSecurityStampAsync(user);
		}

		public Task<bool> VerifyChangePhoneNumberTokenAsync(IdentityUser user, string token, string phoneNumber)
		{
			return _manager.VerifyChangePhoneNumberTokenAsync(user, token, phoneNumber);
		}

		public Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string tokenProvider, string token)
		{
			return _manager.VerifyTwoFactorTokenAsync(user, tokenProvider, token);
		}

		public Task<bool> VerifyUserTokenAsync(IdentityUser user, string tokenProvider, string purpose, string token)
		{
			return _manager.VerifyUserTokenAsync(user, tokenProvider, purpose, token);
		}
	}
}