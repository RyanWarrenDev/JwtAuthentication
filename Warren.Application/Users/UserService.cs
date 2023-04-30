using Warren.Domain.Users;
using Warren.Core.Services.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Warren.Core.Authentication;
using Warren.Core.Services.Email;
using System.Web;
using Warren.Core.Extensions;

namespace Warren.Application.Users
{
    public class UserService : IUserService
    {
        #region Services
        private readonly UserManager<User> _userManager;

        private readonly IHttpContextAccessor _httpContextAccessor;

        private readonly IEmailService _emailService;
        #endregion Services

        public UserService(IHttpContextAccessor httpContextAccessor, UserManager<User> userManager, IEmailService emailService)
        {
            _httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
            _emailService = emailService;
        }

        public async Task<User> GetCurrentUser()
        {
            var userId = _httpContextAccessor?.HttpContext?.User?.FindFirst(JwtAuthClaimTypes.UserId)?.Value;

            if (userId == null)
                return null;

            return await _userManager.FindByIdAsync(userId);
        }

        public async Task<IList<Claim>> GetUserClaimsById(int userId)
        {
            if (userId == default)
                throw new Exception("Cannot get claims without user id");

            var user = await _userManager.FindByIdAsync(userId.ToString());

            if (user == null)
                throw new Exception($"No user found for ID: {userId}");

            var claims = await _userManager.GetClaimsAsync(user);

            return claims;
        }

        public async Task<IList<Claim>> GetUserClaims(User user)
        {
            if (user == null)
                throw new Exception("Cannot get claims from null user");

            var claims = await _userManager.GetClaimsAsync(user);
            return claims.Distinct().ToList();
        }

        public async Task<User> RegisterNewUser(User newUser, string password, string confirmationUrl)
        {
            if (newUser == null)
                throw new Exception("Cannot create null user");

            var creatingUser = await GetCurrentUser();

            newUser.CreatedDate = DateTime.UtcNow;
            newUser.ModifiedDate = DateTime.UtcNow;
            
            var result = await _userManager.CreateAsync(newUser, password);

            if (!result.Succeeded)
                throw new Exception($"Failed to create new user: {newUser.Email}");

            await SendUserConfirmationEmail(confirmationUrl, newUser);

            return newUser;
        }

        public async Task<bool> ConfirmUserEmailTokenAsync(string email, string token)
        {
            //Tenant based, same email can exist on multiple tenants but have different user accounts
            var user = await _userManager.FindByEmailAsync(email.Base64ForUrlDecode());

            //If user doesn't exist then exit
            if (user is null)
                return false;

            //If user is already confirmed exit
            if (user.EmailConfirmed)
                return true;

            //Decode token as passing in URL can corrupt it
            token = token.Base64ForUrlDecode();

            //Validate the token, again on a per tenant basis
            var result = await _userManager.ConfirmEmailAsync(user, token);

            return result.Succeeded;
        }

        public async Task<bool> SendPasswordReset(string email, string resetUrl)
        {
            //Tenant based, same email can exist on multiple tenants but have different user accounts
            var user = await _userManager.FindByEmailAsync(email);

            //If user doesn't exist then exit
            if (user is null)
                return false;

            var result = await SendUserPasswordResetEmail(resetUrl, user);

            return result;
        }

        public async Task<bool> ResetUserPassword(string email, string token, string newPassword)
        {
            //Tenant based, same email can exist on multiple tenants but have different user accounts
            var user = await _userManager.FindByEmailAsync(email.Base64ForUrlDecode());

            //If user doesn't exist then exit
            if (user is null)
                return false;

            //Decode token as passing in URL can corrupt it
            token = token.Base64ForUrlDecode();

            //Validate the token, again on a per tenant basis
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            return result.Succeeded;
        }

        public async Task<User> UpdateUserAsync(User updateUser)
        {
            await _userManager.UpdateAsync(updateUser);
            return updateUser;
        }

        public User DeleteUser(User user)
        {
            throw new NotImplementedException();
        }

        #region Helpers
        private async Task<bool> SendUserConfirmationEmail(string confirmationUrl, User user)
        {
            //Generate confirmation token for user, done on a per tenant basis
            var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //Encode the token to preserve characters during url generation
            confirmationToken = confirmationToken.Base64ForUrlEncode();
            confirmationUrl = $"{confirmationUrl}?email={user.Email.Base64ForUrlEncode()}&token={confirmationToken}";

            var subject = $"Hi {user.Email}, please activate your new account";
            var body = $"Please click the link below to confirm your new account \r\n {confirmationUrl}";

            //Send the confirmation email
            var success = await _emailService.SendEmailAsync(user.Email, subject, body);

            return success;
        }

        private async Task<bool> SendUserPasswordResetEmail(string resetUrl, User user)
        {
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            resetToken = resetToken.Base64ForUrlEncode();

            resetUrl = $"{resetUrl}?email={user.Email.Base64ForUrlEncode()}&token={resetToken}";

            var subject = $"Password reset request";
            var body = $"A password reset request has been made, Please click the link below to create a new password \r\n {resetUrl}";

            //Send the confirmation email
            var success = await _emailService.SendEmailAsync(user.Email, subject, body);

            return success;
        }
        #endregion Helpers
    }
}
