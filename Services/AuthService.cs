using API_JWT_TestOne.Helpers;
using API_JWT_TestOne.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.CodeAnalysis.Options;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using NuGet.Common;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Azure;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace API_JWT_TestOne.Services

{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUsers> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly JWT _jwt;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(UserManager<ApplicationUsers> UserManager, RoleManager<IdentityRole> roleManager, IOptions<JWT> jwt, IHttpContextAccessor httpContextAccessor)
        {
            userManager = UserManager;
            this.roleManager = roleManager;
            _jwt = jwt.Value;
            _httpContextAccessor = httpContextAccessor;
        }
        public async Task<AuthModel> RegisterAsync(RegisterModel Model)
        {
            if (await userManager.FindByEmailAsync(Model.Email) is not null)
                return new AuthModel { Message = "Email is Already registered " };

            if (await userManager.FindByNameAsync(Model.UserName) is not null)
                return new AuthModel { Message = "UserName is Already registered " };

            var user = new ApplicationUsers
            {

                UserName = Model.UserName,
                Email = Model.Email,
                FirstName = Model.FirstName,
                 LastName = Model.LastName,
               

            };

            var result = await userManager.CreateAsync(user,Model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                    errors += $"{error.Description},";


                return new AuthModel { Message = errors };
            }


            await userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                //ExpireOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName
            };




        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel Model)// for login by token
        {
            var authmodel = new AuthModel();
            var user = await userManager.FindByEmailAsync(Model.Email);

            if (user is null)
            {
                authmodel.Message = "Email or Password is incorrect";
                return authmodel;
            }

             if(!await userManager.CheckPasswordAsync(user, Model.Password))
                {
                authmodel.Message = "Email or Password is incorrect";
                return authmodel;
            }
 
            var jwtSecurityToken = await CreateJwtToken(user);
            var RoleList = await userManager.GetRolesAsync(user);

            authmodel.IsAuthenticated = true;
            authmodel.token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authmodel.Email = user.Email;
            authmodel.UserName = user.UserName;
           // authmodel.ExpireOn = jwtSecurityToken.ValidTo;
            authmodel.Roles = RoleList.ToList();


            if(user.RefreshTokens.Any(t=>t.IsActive))
            {
                var activeRefreshtokens=  user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authmodel.RefreshToken = activeRefreshtokens.Token;
                authmodel.RefreshTokenExpiration = activeRefreshtokens.ExpiresOn;

            }
            else
            {
                var refreshtokens = GenerateRefreshTokens();
                authmodel.RefreshToken = refreshtokens.Token;
                authmodel.RefreshTokenExpiration = refreshtokens.ExpiresOn;
                user.RefreshTokens.Add(refreshtokens);
                await userManager.UpdateAsync(user);


            }

            return authmodel;

        }

       public async Task<String> AddRoleAsync(AddRoleModel Model)
        {

            var user = await userManager.FindByIdAsync(Model.UserId);
            
            if (user is null || !await roleManager.RoleExistsAsync(Model.RoleName))
                return "Invalid User ID  or Role Id";

            if (await userManager.IsInRoleAsync(user, Model.RoleName))
                return "user is aleardy assigned";

            var result = await userManager.AddToRoleAsync(user, Model.RoleName);


            return result.Succeeded ? string.Empty : "Something is wrong";


        }








        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUsers user)
        {

            var UserClaims = await userManager.GetClaimsAsync(user);
            var Roles = await userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();
            foreach (var role in Roles)
                roleClaims.Add(new Claim("Roles", role));


            var Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }

            .Union(UserClaims)
            .Union(roleClaims);

            var SymmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(SymmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                 issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: Claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
               signingCredentials: signingCredentials);

            return jwtSecurityToken;

        }
        public RefreshTokens GenerateRefreshTokens()
        {
            var RandomNumber = new byte[32];
            using var generator = new RNGCryptoServiceProvider();

            generator.GetBytes(RandomNumber);
            return new RefreshTokens
            {
               Token= Convert.ToBase64String(RandomNumber),
               CreatedOn = DateTime.UtcNow,
               ExpiresOn= DateTime.UtcNow.AddDays(10)
            };

        }
        public void SetRefreshTokenInCookie(string refreshToken , DateTime expires)
        {

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires.ToLocalTime(),

            };
            _httpContextAccessor.HttpContext.Response.Cookies.Append("refreshtoken", refreshToken, cookieOptions);
        }

         public async Task<AuthModel> RefreshTokenAsync(string token)// generate new refresh token
        {
            var authmodel = new AuthModel();

            var user = await userManager.Users.FirstOrDefaultAsync(u =>u.RefreshTokens.Any(r=>r.Token == token));
            if (user == null)
            {
               //authmodel.IsAuthenticated = false; // already false 
                authmodel.Message = "invalid token";// not give detailed reason for security
                return authmodel;

            }
            var refreshtoken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshtoken.IsActive)
            {

               // authmodel.IsAuthenticated = false;
                authmodel.Message = "invalid token";// inactive token 
                return authmodel;
            }
            refreshtoken.RevokedOn = DateTime.UtcNow;
            var newRefreshToken = GenerateRefreshTokens();
            user.RefreshTokens.Add(newRefreshToken);
            await userManager.UpdateAsync(user);
            var JwtToken = await CreateJwtToken(user);
            authmodel.IsAuthenticated = true;
            authmodel.Email = user.Email;
            authmodel.UserName=user.UserName;
            var roles = await userManager.GetRolesAsync(user);
            authmodel.Roles = roles.ToList();
            authmodel.RefreshToken = newRefreshToken.Token;
            authmodel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;
                return authmodel;

        }

      public async Task<bool> RevokeTokenAsync(string token)// revoke refresh token
        {
            var user = await userManager.Users.FirstOrDefaultAsync(u => u.RefreshTokens.Any(r => r.Token == token));
            if (user == null)
                return false;
 
            var refreshtoken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshtoken.IsActive)
                return false;
          
            
            refreshtoken.RevokedOn = DateTime.UtcNow;
            await userManager.UpdateAsync(user);
            return true;

        }
    }
}
