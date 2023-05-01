using Warren.Core.Authentication;
using Warren.Core.Extensions;
using Warren.Core.Services.Users;
using Warren.Domain.Users;
using Warren.JwtAuth.API.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace Warren.JwtAuth.API.Controllers
{
    public class AccountController : Controller
    {
        #region Services
        private readonly IUserService _userService;

        private readonly IAuthService _authService;

        private readonly LinkGenerator _linkGenerator;

        #endregion Services

        public AccountController(IUserService userService, IAuthService authService, LinkGenerator linkGenerator)
        {
            _userService = userService;
            _authService = authService;
            _linkGenerator = linkGenerator;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody]Login login)
        {
            //Check user's login details are valid and get token
            var authToken = await _authService.Login(login.UserName, login.Password);

            if (authToken is null)
                return Unauthorized();

            //Add cookie to users browser with refresh token for later use
            var cookieOptions = new CookieOptions()
            {
                IsEssential = true,
                Expires = authToken.RefreshTokenValidTo,
                Secure = true,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict
            };
            Response.Cookies.Append("JwtAuth_Refresh", authToken.RefreshToken, cookieOptions);

            return Ok(new
            {
                Token = authToken.EncryptedToken,
                ValidTo = authToken.TokenValidTo,
                RefreshToken = authToken.RefreshToken
            });
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("Refresh")]
        public async Task<IActionResult> Refresh()
        {
            var refreshToken = Request.Cookies["JwtAuth_Refresh"];
            var token = Request.Headers.Authorization.ToString().ToLower().Substring("bearer ".Length);

            if(token.IsNullOrEmpty() || refreshToken.IsNullOrEmpty())
                return Unauthorized();

            var authToken = await _authService.GetAuthTokenFromRefresh(token, refreshToken);

            if (authToken is null)
                return Unauthorized();

            return Ok(new
            {
                Token = authToken.EncryptedToken,
                ValidTo = authToken.TokenValidTo,
                RefreshToken = authToken.RefreshToken
            });
        }

        [HttpPost]
        [Route("RegisterUser")]
        public async Task<IActionResult> RegisterUser([FromBody]RegisterUser newUser)
        {
            var user = newUser.Adapt<User>();

            var confirmationUrl = _linkGenerator.GetUriByAction(Request.HttpContext, "ConfirmEmail");

            user = await _userService.RegisterNewUser(user, newUser.Password, confirmationUrl);

            if (user != null && user.Id != default)
                return Ok(user);

            return BadRequest("Unable to create new user");
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromQuery]string token, [FromQuery]string email)
        {
            if (token.IsNullOrEmpty() || email.IsNullOrEmpty())
                return BadRequest("Must have both token and email address");

            var confirmed = await _userService.ConfirmUserEmailTokenAsync(email, token);

            if (confirmed)
                return Ok("Thanks for confirming your email address");

            return BadRequest("Something went wrong confirming your email address");
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromQuery]string email)
        {
            if (email.IsNullOrEmpty())
                return BadRequest("Must have an email address");

            var resetUrl = _linkGenerator.GetUriByAction(Request.HttpContext, "ChangePassword");

            var success = await _userService.SendPasswordReset(email, resetUrl);

            if (success)
                return Ok("Password reset email sent");

            return BadRequest("Something went wrong trying to reset your password");
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("ChangePassword")]
        public async Task<IActionResult> ChangePassword([FromBody]ChangePassword changePasswordRequest)
        {
            if (changePasswordRequest.Token.IsNullOrEmpty() || changePasswordRequest.Email.IsNullOrEmpty())
                return BadRequest("Must have both token and email address");

            var confirmed = await _userService.ResetUserPassword(changePasswordRequest.Email, changePasswordRequest.Token, changePasswordRequest.NewPassword);

            if (confirmed)
                return Ok("Your password has been reset");

            return BadRequest("Something went wrong changing your password");
        }

        [HttpGet]
        [Route("TestAuth")]
        [Authorize]
        public async Task<IActionResult> TestAuth()
        {
            var user = await _userService.GetCurrentUser();

            if (user != null)
                return Ok("Auth successful");
            else
                return BadRequest("Auth unsuccessful");
        }
    }
}
