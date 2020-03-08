using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace DockerDemo.IdentityServer.Abstractions
{
    public interface ISignInManager
    {
        /// <summary>
		/// The <see cref="T:Microsoft.AspNetCore.Identity.IUserClaimsPrincipalFactory`1" /> used.
		/// </summary>
		IUserClaimsPrincipalFactory<IdentityUser> ClaimsFactory { get; set; }

		/// <summary>
		/// The <see cref="T:Microsoft.AspNetCore.Http.HttpContext" /> used.
		/// </summary>
		HttpContext Context { get; set; }

		/// <summary>
		/// Gets the <see cref="T:Microsoft.Extensions.Logging.ILogger" /> used to log messages from the manager.
		/// </summary>
		/// <value>
		/// The <see cref="T:Microsoft.Extensions.Logging.ILogger" /> used to log messages from the manager.
		/// </value>
		ILogger Logger { get; set; }

		/// <summary>
		/// The <see cref="T:Microsoft.AspNetCore.Identity.IdentityOptions" /> used.
		/// </summary>
		IdentityOptions Options { get; set; }

		/// <summary>
		/// The <see cref="T:Microsoft.AspNetCore.Identity.UserManager`1" /> used.
		/// </summary>
		UserManager<IdentityUser> UserManager { get; set; }

		/// <summary>
		/// Returns a flag indicating whether the specified user can sign in.
		/// </summary>
		/// <param name="user">The user whose sign-in status should be returned.</param>
		/// <returns>
		/// The task object representing the asynchronous operation, containing a flag that is true
		/// if the specified user can sign-in, otherwise false.
		/// </returns>
		Task<bool> CanSignInAsync(IdentityUser user);

		/// <summary>Attempts a password sign in for a user.</summary>
		/// <param name="user">The user to sign in.</param>
		/// <param name="password">The password to attempt to sign in with.</param>
		/// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		/// <returns></returns>
		Task<SignInResult> CheckPasswordSignInAsync(IdentityUser user,
													string password,
													bool lockoutOnFailure);

		/// <summary>
		/// Configures the redirect URL and user identifier for the specified external login <paramref name="provider" />.
		/// </summary>
		/// <param name="provider">The provider to configure.</param>
		/// <param name="redirectUrl">The external login URL users should be redirected to during the login flow.</param>
		/// <param name="userId">The current user's identifier, which will be used to provide CSRF protection.</param>
		/// <returns>A configured <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" />.</returns>
		AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider,
																			string redirectUrl,
																			string userId = null);

		/// <summary>
		/// Creates a <see cref="T:System.Security.Claims.ClaimsPrincipal" /> for the specified <paramref name="user" />, as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user to create a <see cref="T:System.Security.Claims.ClaimsPrincipal" /> for.</param>
		/// <returns>The task object representing the asynchronous operation, containing the ClaimsPrincipal for the specified user.</returns>
		Task<ClaimsPrincipal> CreateUserPrincipalAsync(IdentityUser user);

		/// <summary>
		/// Signs in a user via a previously registered third party login, as an asynchronous operation.
		/// </summary>
		/// <param name="loginProvider">The login provider to use.</param>
		/// <param name="providerKey">The unique provider identifier for the user.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		Task<SignInResult> ExternalLoginSignInAsync(string loginProvider,
													string providerKey,
													bool isPersistent);

		/// <summary>
		/// Signs in a user via a previously registered third party login, as an asynchronous operation.
		/// </summary>
		/// <param name="loginProvider">The login provider to use.</param>
		/// <param name="providerKey">The unique provider identifier for the user.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="bypassTwoFactor">Flag indicating whether to bypass two factor authentication.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		Task<SignInResult> ExternalLoginSignInAsync(string loginProvider,
													string providerKey,
													bool isPersistent,
													bool bypassTwoFactor);

		/// <summary>
		/// Clears the "Remember this browser flag" from the current browser, as an asynchronous operation.
		/// </summary>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task ForgetTwoFactorClientAsync();

		/// <summary>
		/// Gets a collection of <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationScheme" />s for the known external login providers.
		/// </summary>
		/// <returns>A collection of <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationScheme" />s for the known external login providers.</returns>
		Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync();

		/// <summary>
		/// Gets the external login information for the current login, as an asynchronous operation.
		/// </summary>
		/// <param name="expectedXsrf">Flag indication whether a Cross Site Request Forgery token was expected in the current request.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="ExternalLoginInfo" />
		/// for the sign-in attempt.</returns>
		Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null);

		/// <summary>
		/// Gets the <typeparamref name="IdentityUser" /> for the current two factor authentication login, as an asynchronous operation.
		/// </summary>
		/// <returns>The task object representing the asynchronous operation containing the <typeparamref name="IdentityUser" />
		/// for the sign-in attempt.</returns>
		Task<IdentityUser> GetTwoFactorAuthenticationUserAsync();

		/// <summary>
		/// Returns true if the principal has an identity with the application cookie identity
		/// </summary>
		/// <param name="principal">The <see cref="T:System.Security.Claims.ClaimsPrincipal" /> instance.</param>
		/// <returns>True if the user is logged in with identity.</returns>
		bool IsSignedIn(ClaimsPrincipal principal);

		/// <summary>
		/// Returns a flag indicating if the current client browser has been remembered by two factor authentication
		/// for the user attempting to login, as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user attempting to login.</param>
		/// <returns>
		/// The task object representing the asynchronous operation containing true if the browser has been remembered
		/// for the current user.
		/// </returns>
		Task<bool> IsTwoFactorClientRememberedAsync(IdentityUser user);

		/// <summary>
		/// Attempts to sign in the specified <paramref name="userName" /> and <paramref name="password" /> combination
		/// as an asynchronous operation.
		/// </summary>
		/// <param name="userName">The user name to sign in.</param>
		/// <param name="password">The password to attempt to sign in with.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		Task<SignInResult> PasswordSignInAsync(string userName,
												string password,
												bool isPersistent,
												bool lockoutOnFailure);

		/// <summary>
		/// Attempts to sign in the specified <paramref name="user" /> and <paramref name="password" /> combination
		/// as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user to sign in.</param>
		/// <param name="password">The password to attempt to sign in with.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		Task<SignInResult> PasswordSignInAsync(IdentityUser user,
												string password,
												bool isPersistent,
												bool lockoutOnFailure);

		/// <summary>
		/// Regenerates the user's application cookie, whilst preserving the existing
		/// AuthenticationProperties like rememberMe, as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user whose sign-in cookie should be refreshed.</param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task RefreshSignInAsync(IdentityUser user);

		/// <summary>
		/// Sets a flag on the browser to indicate the user has selected "Remember this browser" for two factor authentication purposes,
		/// as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user who choose "remember this browser".</param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task RememberTwoFactorClientAsync(IdentityUser user);

		/// <summary>
		/// Signs in the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to sign-in.</param>
		/// <param name="authenticationProperties">Properties applied to the login and authentication cookie.</param>
		/// <param name="authenticationMethod">Name of the method used to authenticate the user.</param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task SignInAsync(IdentityUser user,
						AuthenticationProperties authenticationProperties,
						string authenticationMethod = null);

		/// <summary>
		/// Signs in the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to sign-in.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="authenticationMethod">Name of the method used to authenticate the user.</param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task SignInAsync(IdentityUser user, bool isPersistent, string authenticationMethod = null);

		/// <summary>
		/// Signs in the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to sign-in.</param>
		/// <param name="authenticationProperties">Properties applied to the login and authentication cookie.</param>
		/// <param name="additionalClaims">Additional claims that will be stored in the cookie.</param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task SignInWithClaimsAsync(IdentityUser user,
									AuthenticationProperties authenticationProperties,
									IEnumerable<Claim> additionalClaims);

		/// <summary>
		/// Signs in the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to sign-in.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="additionalClaims">Additional claims that will be stored in the cookie.</param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		Task SignInWithClaimsAsync(IdentityUser user,
									bool isPersistent,
									IEnumerable<Claim> additionalClaims);

		/// <summary>Signs the current user out of the application.</summary>
		Task SignOutAsync();

		/// <summary>
		/// Validates the sign in code from an authenticator app and creates and signs in the user, as an asynchronous operation.
		/// </summary>
		/// <param name="code">The two factor authentication code to validate.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="rememberClient">Flag indicating whether the current browser should be remember, suppressing all further
		/// two factor authentication prompts.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code,
															bool isPersistent,
															bool rememberClient);

		/// <summary>
		/// Signs in the user without two factor authentication using a two factor recovery code.
		/// </summary>
		/// <param name="recoveryCode">The two factor recovery code.</param>
		/// <returns></returns>
		Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode);

		/// <summary>
		/// Validates the two factor sign in code and creates and signs in the user, as an asynchronous operation.
		/// </summary>
		/// <param name="provider">The two factor authentication provider to validate the code against.</param>
		/// <param name="code">The two factor authentication code to validate.</param>
		/// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
		/// <param name="rememberClient">Flag indicating whether the current browser should be remember, suppressing all further
		/// two factor authentication prompts.</param>
		/// <returns>The task object representing the asynchronous operation containing the <see name="SignInResult" />
		/// for the sign-in attempt.</returns>
		Task<SignInResult> TwoFactorSignInAsync(string provider,
												string code,
												bool isPersistent,
												bool rememberClient);

		/// <summary>
		/// Stores any authentication tokens found in the external authentication cookie into the associated user.
		/// </summary>
		/// <param name="externalLogin">The information from the external login provider.</param>
		/// <returns>The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation, containing the <see cref="T:Microsoft.AspNetCore.Identity.IdentityResult" /> of the operation.</returns>
		Task<IdentityResult> UpdateExternalAuthenticationTokensAsync(ExternalLoginInfo externalLogin);

		/// <summary>
		/// Validates the security stamp for the specified <paramref name="principal" /> against
		/// the persisted stamp for the current user, as an asynchronous operation.
		/// </summary>
		/// <param name="principal">The principal whose stamp should be validated.</param>
		/// <returns>The task object representing the asynchronous operation. The task will contain the <typeparamref name="IdentityUser" />
		/// if the stamp matches the persisted value, otherwise it will return false.</returns>
		Task<IdentityUser> ValidateSecurityStampAsync(ClaimsPrincipal principal);

		/// <summary>
		/// Validates the security stamp for the specified <paramref name="user" />. Will always return false
		/// if the userManager does not support security stamps.
		/// </summary>
		/// <param name="user">The user whose stamp should be validated.</param>
		/// <param name="securityStamp">The expected security stamp value.</param>
		/// <returns>True if the stamp matches the persisted value, otherwise it will return false.</returns>
		Task<bool> ValidateSecurityStampAsync(IdentityUser user, string securityStamp);

		/// <summary>
		/// Validates the security stamp for the specified <paramref name="principal" /> from one of
		/// the two factor principals (remember client or user id) against
		/// the persisted stamp for the current user, as an asynchronous operation.
		/// </summary>
		/// <param name="principal">The principal whose stamp should be validated.</param>
		/// <returns>The task object representing the asynchronous operation. The task will contain the <typeparamref name="IdentityUser" />
		/// if the stamp matches the persisted value, otherwise it will return false.</returns>
		Task<IdentityUser> ValidateTwoFactorSecurityStampAsync(ClaimsPrincipal principal);
    }
}