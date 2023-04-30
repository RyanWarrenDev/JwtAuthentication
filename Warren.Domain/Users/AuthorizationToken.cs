using Warren.Domain.Auditing;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace Warren.Domain.Users
{
    public class AuthorizationToken : Entity
    {
        /// <summary>
        /// Don't store the token in the database
        /// </summary>
        [NotMapped]
        public string EncryptedToken { get; set; }

        public string RefreshToken { get; set; }

        public DateTime TokenValidTo { get; set; }

        public DateTime RefreshTokenValidTo { get; set; }

        public bool TokenRevoked { get; set; }

        public virtual int UserId { get; set; }
    }
}
