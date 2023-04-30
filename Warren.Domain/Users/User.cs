using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System;
using Microsoft.AspNetCore.Identity;
using Warren.Domain.Auditing;

namespace Warren.Domain.Users
{
    public class User : IdentityUser<int>, ICreatedModifiedDate, ISoftDelete
    {
        public DateTime CreatedDate { get; set; }

        public DateTime ModifiedDate { get; set; }

        public virtual bool? IsDeleted { get; set; }

        [MaxLength(20), Required]
        public string Title { get; set; }

        [MaxLength(50), Required]
        public string Forename { get; set; }

        [MaxLength(50), Required]
        public string Surname { get; set; }

        [Required]
        public DateTime DOB { get; set; }

        public AuthorizationToken? AuthorizationToken { get; set; }

        public UserRole UserRole { get; set; }

        [NotMapped]
        public string Fullname => $"{Forename} {Surname}";
    }
}
