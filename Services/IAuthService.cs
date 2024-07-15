
using API_JWT_TestOne.Models;
namespace API_JWT_TestOne.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel Model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel Model);
        Task<String> AddRoleAsync(AddRoleModel Model);
        RefreshTokens GenerateRefreshTokens();
         void SetRefreshTokenInCookie(string refreshToken, DateTime expires);
        Task<AuthModel> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);


    }
}
