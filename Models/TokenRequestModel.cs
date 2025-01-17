﻿using System.ComponentModel.DataAnnotations;

namespace API_JWT_TestOne.Models
{
    public class TokenRequestModel
    {
        [Required]
        public string? Email { get; set; }

        [Required]
        public string? Password { get; set; }
    }

}
