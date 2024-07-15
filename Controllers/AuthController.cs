using API_JWT_TestOne.Models;
using API_JWT_TestOne.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;


namespace API_JWT_TestOne.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService iAuthService;
     

        public AuthController(IAuthService _IAuthService)
        {
            iAuthService = _IAuthService;
            
        }
        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync ([FromBody]RegisterModel Model)
        {
            if(!ModelState.IsValid) 
                return BadRequest(ModelState);

       var result =await iAuthService.RegisterAsync(Model);
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            iAuthService.SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);// set refresh token to registered user
            //return Ok(result);

            //return Ok(new { Token = result.token, expirOn = result.ExpireOn });
            return Ok(new { Token = result.token});


        }
        [HttpPost("Token")]
        public async Task<IActionResult> GetTokenAsync([FromBody]  TokenRequestModel Model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await iAuthService.GetTokenAsync(Model);
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            if(! string.IsNullOrEmpty(result.RefreshToken))
                iAuthService.SetRefreshTokenInCookie(result.RefreshToken,result.RefreshTokenExpiration);



            return Ok(result);
            //return Ok(new { Token = result.token, expirOn = result.ExpireOn }); 
        }

        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel Model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            
            var result = await iAuthService.AddRoleAsync(Model);
            
            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);


            return Ok(Model);
            //return Ok(new { Token = result.token, expirOn = result.ExpireOn }); 
        }

        [HttpGet("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshtoken"];
            var result = await iAuthService.RefreshTokenAsync(refreshToken);
            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

          iAuthService.SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
            return Ok(result);


        }

        [HttpPost("RevokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model)
        {
            var token = model.token ?? Request.Cookies["refreshtoken"];// ?? mean if model is null execute Request.Cookies     
            if (string.IsNullOrEmpty(token))
                return BadRequest("Token is required");
            var result = await iAuthService.RevokeTokenAsync(token);

            if (!result)
                return BadRequest("Token is invalid");

            return Ok();


        }










    }
}