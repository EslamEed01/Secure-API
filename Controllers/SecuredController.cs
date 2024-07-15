using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace API_JWT_TestOne.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        [HttpGet]
        public  IActionResult GetData()
        {
            return Ok("hello from secured controller");
        }
    }
}
