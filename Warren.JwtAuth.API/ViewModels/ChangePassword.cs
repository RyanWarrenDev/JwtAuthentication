namespace Warren.JwtAuth.API.ViewModels
{
    public class ChangePassword
    {
        public string Email { get; set; }

        public string Token { get; set; }

        public string NewPassword { get; set; }
    }
}
