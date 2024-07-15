using Microsoft.EntityFrameworkCore;

namespace API_JWT_TestOne.Models
{
    [Owned]
    public class RefreshTokens
    {


        public string? Token { get; set; }
        public DateTime ExpiresOn { get; set; }
        public bool IsExpired => DateTime.Now >= ExpiresOn;
        public DateTime CreatedOn { get; set; }
        public DateTime? RevokedOn { get; set; }
        public bool IsActive => RevokedOn == null && !IsExpired;
    }

}
