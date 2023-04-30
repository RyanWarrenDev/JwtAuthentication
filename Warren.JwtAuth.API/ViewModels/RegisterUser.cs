using Warren.Domain.Users;
using System.ComponentModel.DataAnnotations;

namespace Warren.JwtAuth.API.ViewModels
{
    public class RegisterUser
    {
        [MaxLength(30), Required]
        public string UserName { get; set; }

        [MaxLength(50), Required]
        public string Password { get; set; }

        [MaxLength(50), Required]
        public string Email { get; set; }

        [MaxLength(30), Required]
        public string Forename { get; set; }

        [MaxLength(30), Required]
        public string Surname { get; set; }

        [MaxLength(20), Required]
        public string Title { get; set; }

        [Required]
        public DateTime DateOfBirth { get; set; }

        [MaxLength(20), Required]
        public string Gender { get; set; }

        [MaxLength(50), Required]
        public string Ethnicity { get; set; }

        [MaxLength(30), Required]
        public string PreferredName { get; set; }

        [MaxLength(20), Required]
        public string IdentifyAsGender { get; set; }

        public string PhoneNumber { get; set; }

        public UserRole UserRole { get; set; }
    }
}
