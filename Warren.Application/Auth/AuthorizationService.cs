﻿using Warren.Core.Authentication;
using Warren.Core.Extensions;
using Warren.Core.Repositories;
using Warren.Domain.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Warren.Application.Auth
{
    public class AuthorizationService : IAuthService
    {
        private readonly IConfiguration _configuration;

        private readonly IRepository<AuthorizationToken> _authRepository;

        private readonly UserManager<User> _userManager;

        public const int DEFAULTTOKENEXPIRESINMINUTES = 10;
        public const int DEFAULTREFRESHEXPIRYTIMEDAYS = 10;

        private int _tokenExpiresInMinutes { get; set; }
        private int TokenExpiresInMinutes
        {
            get
            {
                if (_tokenExpiresInMinutes == default)
                    _tokenExpiresInMinutes = _configuration["JWTSettings:ExpiresInMinutes"]
                                                .ToInt(DEFAULTTOKENEXPIRESINMINUTES);
                return _tokenExpiresInMinutes;
            }
        }

        private int _refreshTokenExpiresInDays { get; set; }
        private int RefreshTokenExpiresInDays
        {
            get
            {
                if (_refreshTokenExpiresInDays == default)
                    _refreshTokenExpiresInDays = _configuration["JWTSettings:RefreshExpiresInDays"]
                                                .ToInt(DEFAULTREFRESHEXPIRYTIMEDAYS);
                return _refreshTokenExpiresInDays;
            }
        }

        private byte[] _secretKey { get; set; }
        private byte[] SecretKey
        {
            get
            {
                if (_secretKey.IsNullOrEmpty())
                    _secretKey = Encoding.UTF8.GetBytes(_configuration["JWTSettings:SecretKey"]);
                return _secretKey;
            }
        }

        private byte[] _encryptionKey { get; set; }
        private byte[] EncryptionKey
        {
            get
            {
                if (_encryptionKey.IsNullOrEmpty())
                    _encryptionKey = Encoding.UTF8.GetBytes(_configuration["JWTSettings:EncryptionKey"]);
                return _encryptionKey;
            }
        }

        private string _issuer { get; set; }
        private string Issuer { 
            get
            {
                if (_issuer.IsNullOrEmpty())
                    _issuer = _configuration["JWTSettings:Issuer"];
                return _issuer;
            } 
        }

        private string _audience { get; set; }
        private string Audience
        {
            get
            {
                if (_audience.IsNullOrEmpty())
                    _audience = _configuration["JWTSettings:Audience"];
                return _audience;
            }
        }

        public AuthorizationService(IConfiguration configuration, IRepository<AuthorizationToken> authRepository, UserManager<User> userManager)
        {
            _configuration = configuration;
            _authRepository = authRepository;
            _userManager = userManager;
        }

        public async Task<AuthorizationToken?> Login(string username, string password)
        {
            //Check user's login details are valid
            var user = await ValidateLogin(username, password);

            //If user isn't found don't create a token
            if (user is null)
                return null;

            //Create auth token
            var authToken = await GetAuthToken(user);
            
            return authToken;
        }

        public async Task<User> ValidateLogin(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                throw new Exception("Cannot validate login without both username and password");

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                throw new Exception($"User: {username} not found");

            var isValidLogin = await _userManager.CheckPasswordAsync(user, password);

            if (!isValidLogin)
                throw new Exception($"Login details not correct for user {username}");

            return user;
        }

        public async Task<AuthorizationToken?> GetAuthTokenFromRefresh(string token, string refreshToken)
        {
            var tokenUser = GetPrincipalFromExpiredToken(token);
            if (tokenUser == null)
                throw new UnauthorizedAccessException("Could not verify token");

            var authToken = _authRepository.FindBy(x => x.RefreshToken == refreshToken).SingleOrDefault();

            if (authToken is null || DateTime.UtcNow >= authToken.RefreshTokenValidTo || authToken.TokenRevoked)
                throw new UnauthorizedAccessException("Refresh token is not valid");

            var user = await _userManager.FindByIdAsync(authToken.UserId.ToString());

            if (user == null || tokenUser.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value != user.Email)
                throw new UnauthorizedAccessException("Refresh token does not match access token");

            return await GetAuthToken(user);
        }

        #region Helpers
        private async Task<AuthorizationToken> GetAuthToken(User user)
        {
            var tokenValidTo = DateTime.UtcNow.AddMinutes(TokenExpiresInMinutes);

            //Create encryption keys
            var symmetricKey = new SymmetricSecurityKey(EncryptionKey);
            var encryptionCredentials = new EncryptingCredentials(symmetricKey, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes256CbcHmacSha512);

            //Get claims identity to add to the token
            var claimsIdentity = await GetClaimsIdentityAsync(user);

            //Create the jwt token definition
            var jwtToken = new JwtSecurityTokenHandler().CreateJwtSecurityToken(
                Issuer,
                Audience,
                claimsIdentity,
                DateTime.UtcNow,
                tokenValidTo,
                DateTime.UtcNow,
                new SigningCredentials(new SymmetricSecurityKey(SecretKey), SecurityAlgorithms.HmacSha256Signature),
                encryptionCredentials
            );

            //Create the encrypted token
            var tokenHandler = new JwtSecurityTokenHandler();
            var encryptedToken = tokenHandler.WriteToken(jwtToken);

            //Create auth token object
            var authToken = CreateAuthToken(encryptedToken, tokenValidTo);

            //Store auth token against user
            await StoreUserAuthToken(user, authToken);

            return authToken;
        }

        private AuthorizationToken CreateAuthToken(string token, DateTime tokenValidTo)
        {
            var refreshTokenValidTo = DateTime.UtcNow.AddDays(RefreshTokenExpiresInDays);

            var refreshToken = GenerateRefreshToken();

            var userAuthToken = new AuthorizationToken
            {
                EncryptedToken = token,
                TokenValidTo = tokenValidTo,
                TokenRevoked = false,
                RefreshToken = refreshToken,
                RefreshTokenValidTo = refreshTokenValidTo,
                CreatedDate = DateTime.UtcNow,
                ModifiedDate = DateTime.UtcNow
            };

            return userAuthToken;
        }

        private async Task StoreUserAuthToken(User user, AuthorizationToken authorizationToken)
        {
            //We only store one record of user tokens, delete if already exists.
            //If JWT already generated it will be valid but the RefreshToken will not
            var existingToken = _authRepository.FindBy(i => i.UserId == user.Id).SingleOrDefault();
            if (existingToken is not null)
            {
                _authRepository.Delete(existingToken);
            }

            user.AuthorizationToken = authorizationToken;
            await _userManager.UpdateAsync(user);
        }

        private async Task<ClaimsIdentity> GetClaimsIdentityAsync(User user)
        {
            var claimsIdentity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user.Fullname),
                new Claim(JwtAuthClaimTypes.UserId, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email)
            });

            var userClaims = await _userManager.GetClaimsAsync(user);
            if (userClaims.Any())
                claimsIdentity.AddClaims(userClaims);

            return claimsIdentity;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = false,
                    IssuerSigningKey = new SymmetricSecurityKey(SecretKey),
                    TokenDecryptionKey = new SymmetricSecurityKey(EncryptionKey),
                    ValidateLifetime = false
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

                if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    throw new SecurityTokenException("Invalid token");

                return principal;

            }catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return null;
        }
        #endregion Helpers
    }
}
