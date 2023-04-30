using Warren.Core.Extensions;
using Warren.Core.Services.Email;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Warren.Application.Email
{
    public class EmailService : IEmailService
    {
        #region Services
        private readonly IConfiguration _configuration;
        #endregion Services

        #region Properties
        private string Host { get; set; }

        private int Port { get; set; }

        private string FromAddress { get; set; }

        private string Username{ get; set; }

        private string Password { get; set; }
        #endregion Properties

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
            SetupConfiguration();
        }

        public async Task<bool> SendEmailAsync(string to, string subject, string body, string? from = null)
        {
            if (to.IsNullOrEmpty() || subject.IsNullOrEmpty() || body.IsNullOrEmpty())
                return false;

            using(var mail = new MailMessage())
            {
                from ??= FromAddress;

                mail.From = new MailAddress(from);
                mail.To.Add(to);
                mail.Subject = subject;
                mail.Body = body;

                using(var smtpClient = new SmtpClient(Host, Port))
                {
                    smtpClient.Credentials = new NetworkCredential(Username, Password);

                    await smtpClient.SendMailAsync(mail);
                }
            };

            return true;
        }

        #region Helpers
        private void SetupConfiguration()
        {
            Host = _configuration["SMTP:Host"];
            Port = _configuration["SMTP:Port"].ToInt(1025);
            FromAddress = _configuration["SMTP:FromAddress"];
            Username = _configuration["SMTP:Username"];
            Password = _configuration["SMTP:Password"];
        }
        #endregion Helpers
    }
}
