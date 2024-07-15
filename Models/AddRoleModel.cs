using System.ComponentModel.DataAnnotations;

namespace API_JWT_TestOne.Models
{
    public class AddRoleModel
    {
        [Required]
        public string UserId { get; set; }
        [Required]
        public string RoleName { get; set; }
    }
}
