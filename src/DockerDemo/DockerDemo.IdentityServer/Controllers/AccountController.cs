using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using DockerDemo.IdentityServer.Abstractions;
using DockerDemo.IdentityServer.Exceptions;
using DockerDemo.IdentityServer.Models;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using Serilog.Events;

namespace DockerDemo.IdentityServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly ISignInManager _signInManager;

        private readonly IAuthService _authService;

        private readonly ILogger _logger;

        private readonly IEventService _events;

        private readonly IPersistedGrantStore _persistedGrantStore;

        private readonly IPersistedGrantService _persistedGrantService;

        private readonly IUserSession _userSession;

        private readonly IIdentityServerInteractionService _interaction;

        /// <inheritdoc />
        public AccountController(ISignInManager signInManager, IAuthService authService, ILogger logger,
            IEventService events,
            IPersistedGrantStore persistedGrantStore,
            IUserSession userSession, IIdentityServerInteractionService interaction,
            IPersistedGrantService persistedGrantService)
        {
            _signInManager = signInManager;
            _authService = authService;
            _logger = logger;
            _events = events;
            _persistedGrantStore = persistedGrantStore;
            _userSession = userSession;
            _interaction = interaction;
            _persistedGrantService = persistedGrantService;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View(new LoginViewModel());
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                await _authService.AuthAsync(model).ConfigureAwait(false);

                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning("Пользователь {Email} успешно вошел в систему", model.Email);
                }

                return RedirectToLocal(model.ReturnUrl);
            }
            catch (UserLockedOutException ex)
            {
                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning(ex, ex.Message);
                }

                throw;
            }
            catch (UserNotFoundException ex)
            {
                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning(ex, ex.Message);
                }

                throw;
            }
            catch (EmailNotConfirmedException ex)
            {
                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning(ex, ex.Message);
                }

                throw;
            }
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel model)
        {
            await FullLogOut().ConfigureAwait(false);
            var idp = User?.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
            var subjectId = HttpContext.User.Identity.GetSubjectId();

            if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
            {
                if (model.LogoutId == null)
                {
                    // if there's no current logout context, we need to create one
                    // this captures necessary info from the current logged in user
                    // before we signout and redirect away to the external IdP for signout
                    model.LogoutId = await _interaction.CreateLogoutContextAsync().ConfigureAwait(false);
                }

                try
                {
                    await _signInManager.SignOutAsync().ConfigureAwait(false);
                }
                catch (NotSupportedException)
                {
                }
            }

            // delete authentication cookie
            await _signInManager.SignOutAsync().ConfigureAwait(false);

            // set this so UI rendering sees an anonymous user
            HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(model.LogoutId).ConfigureAwait(false);

            var vm = new LoggedOutViewModel
            {
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = logout?.ClientId,
                SignOutIframeUrl = logout?.SignOutIFrameUrl
            };

            await _persistedGrantService.RemoveAllGrantsAsync(subjectId, logout.ClientId).ConfigureAwait(false);

            return View("LoggedOut", vm);
        }

        /// <summary>
        /// Выйти из системы.
        /// </summary>
        /// <example>
        /// POST: /Account/Logout
        /// </example>
        /// <returns>
        /// Представление выхода из системы
        /// </returns>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            await FullLogOut().ConfigureAwait(false);

            if (User.Identity.IsAuthenticated == false)
            {
                // if the user is not authenticated, then just show logged out page
                return await Logout(new LogoutViewModel {LogoutId = logoutId}).ConfigureAwait(false);
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId).ConfigureAwait(false);

            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                return await Logout(new LogoutViewModel {LogoutId = logoutId}).ConfigureAwait(false);
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            var vm = new LogoutViewModel
            {
                LogoutId = logoutId
            };

            return View(vm);
        }

        [HttpGet]
        public IActionResult ResetPassword(ResetPasswordViewModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPasswordComplete(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(nameof(ResetPassword), model);
            }

            try
            {
                await _authService.ResetPasswordAsync(model.Email, model.Token, model.Password).ConfigureAwait(false);
            }
            catch (ResetPasswordException ex)
            {
                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning(ex, ex.Message);
                }

                throw;
            }
            catch (UserNotFoundException ex)
            {
                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning(ex, ex.Message);
                }

                throw;
            }

            return View(nameof(Login),
                new LoginViewModel
                {
                    Email = model.Email,
                    Password = model.Password
                });
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View(new ForgotPasswordModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                // await _accountService.ForgotPasswordAsync(model.Email).ConfigureAwait(false);

                return View(nameof(ForgotPasswordComplete), model);
            }
            catch (UserNotFoundException ex)
            {
                if (_logger.IsEnabled(LogEventLevel.Warning))
                {
                    _logger.Warning(ex, ex.Message);
                }

                ModelState.AddModelError(nameof(ForgotPassword), "Пользователь не найден");

                return View(model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ForgotPasswordComplete(ForgotPasswordModel model)
        {
            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string email, string token)
        {
            // await _accountService.ConfirmEmailAsync(email, token).ConfigureAwait(false);

            return RedirectToLocal(null);
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            var queryParams = Flurl.Url.ParseQueryParams(returnUrl);

            if (!queryParams.Exists(x => x.Name.Contains("post_logout_redirect_uri")))
            {
                return LocalRedirect(returnUrl);
            }

            var url = queryParams.Find(x => x.Name.Contains("post_logout_redirect_uri")).Value as string;

            return Redirect(url);
        }

        /// <summary>
        /// Fulls the log out.
        /// </summary>
        /// <returns> </returns>
        private async Task FullLogOut()
        {
            var subjectId = User.Identity.GetSubjectId();

            var sessionId = await _userSession.GetSessionIdAsync().ConfigureAwait(false);

            var grants = await _persistedGrantStore.GetAllAsync(subjectId).ConfigureAwait(false);

            foreach (var persistedGrant in grants.Where(e => e.Data.Contains($"\"{sessionId}\"")))
            {
                await _persistedGrantStore.RemoveAsync(persistedGrant.Key).ConfigureAwait(false);
            }

            var keys = Request.Cookies.Keys;

            foreach (var key in keys)
            {
                Response.Cookies.Delete(key);
            }

            await _signInManager.SignOutAsync().ConfigureAwait(false);
            await HttpContext.SignOutAsync().ConfigureAwait(false);
            await _interaction.RevokeTokensForCurrentSessionAsync().ConfigureAwait(false);
            await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()))
                .ConfigureAwait(false);
        }
    }
}