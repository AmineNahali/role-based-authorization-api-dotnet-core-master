using System.ComponentModel.DataAnnotations;

namespace WebApi.Models.Users
{
    public class RegisterRequest
    {
        [Required]
        [MinLength(2)]
        [RegularExpression(@"^[A-Z][a-zA-Z'’-]+(?:\s[A-Z][a-zA-Z'’-]+)*$",
            ErrorMessage = "invalid name format")]
        public string FirstName { get; set; }
        
        [Required]
        [MinLength(2)]
        [RegularExpression(@"^[A-Z][a-zA-Z'’-]+(?:\s[A-Z][a-zA-Z'’-]+)*$",
            ErrorMessage = "invalid name format")]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(8)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            ErrorMessage = "Password must be at least 8 characters long, include lowercase, uppercase, numbers, and special characters.")]
        public string Password1 { get; set; }
        
        [Required]
        [Compare("Password1")]
        public string Password2 { get; set; }
    }
}
