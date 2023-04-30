
using Warren.Domain.Users;
using System.Security.Claims;

namespace Warren.Core.Services.Users
{
    public interface IUserService
    {
        Task<User> GetCurrentUser();

        Task<IList<Claim>> GetUserClaimsById(int userId);

        Task<IList<Claim>> GetUserClaims(User user);

        Task<User> RegisterNewUser(User newUser, string password, string confirmationUrl);

        Task<bool> SendPasswordReset(string email, string resetUrl);

        Task<bool> ResetUserPassword(string email, string token, string newPassword);

        Task<bool> ConfirmUserEmailTokenAsync(string email, string token);

        Task<User> UpdateUserAsync(User updateUser);

        User DeleteUser(User user);

    }
}
