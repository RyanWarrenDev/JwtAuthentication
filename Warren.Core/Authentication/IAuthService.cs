using Warren.Domain.Users;

namespace Warren.Core.Authentication
{
    public interface IAuthService
    {
        Task<AuthorizationToken?> Login(string username, string password);

        Task<AuthorizationToken?> GetAuthTokenFromRefresh(string token, string refreshToken);
    }
}
