using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace API_JWT_TestOne.Models
{
    public class ApplicationUsers:IdentityUser
    {
        [Required,MaxLength(30)]
        public string? FirstName {  get; set; }


        [Required, MaxLength(30)]
        public string? LastName { get; set; }

        
        public List<RefreshTokens>? RefreshTokens { get; set; }

    }
}
