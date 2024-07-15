using System.Text.Json.Serialization;

namespace API_JWT_TestOne.Models
{
    public class AuthModel
    {

        public string ? Message { get; set; }
        public bool IsAuthenticated {  get; set; }
        public string ? UserName { get; set; }
        public string ? Email { get; set; }

        public List<string> ? Roles { get; set; }
        public string? token {  get; set; }
       // public DateTime ExpireOn {  get; set; }

        [JsonIgnore]
        public string? RefreshToken {  get; set; }

        public DateTime  RefreshTokenExpiration {  get; set; } 


    }
}
