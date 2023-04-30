using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Warren.Core.Authentication
{
    public class AuthResponse
    {
        public bool Success { get; set; }

        public string Error { get; set; }

        public string EncryptedToken { get; set; }

        public string RefreshToken { get; set; }

        public DateTime TokenValidTo { get; set; }
    }
}
