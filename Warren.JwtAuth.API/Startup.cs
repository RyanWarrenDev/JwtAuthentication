using Warren.Application.Auth;
using Warren.Application.Email;
using Warren.Application.Users;
using Warren.Core.Authentication;
using Warren.Core.Repositories;
using Warren.Core.Services.Email;
using Warren.Core.Services.Users;
using Warren.Domain.Users;
using Warren.EntityFramework;
using Warren.EntityFramework.Repositories;
using Warren.JwtAuth.API.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.OpenApi.Models;

namespace Warren.JwtAuth.API
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            //Add database context to JwtAuth and open connection
            services.AddEntityFrameworkSqlServer()
                .AddDbContext<JwtAuthContext>(o =>
                {
                    o.UseSqlServer(Configuration.GetConnectionString("JwtAuth"));
                });

            services.AddIdentity<User, IdentityRole<int>>()
                .AddEntityFrameworkStores<JwtAuthContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(opts =>
            {
                opts.User.RequireUniqueEmail = false;
                opts.Password.RequiredLength = 8;

                opts.SignIn.RequireConfirmedEmail = true;
            });

            IdentityModelEventSource.ShowPII = true;

            //Add Configuration to container to allow fetching of config values throughout the application
            services.AddSingleton<IConfiguration>(Configuration);
            //Add HttpContextAccessor to have access to HttpContext throughout application
            services.AddHttpContextAccessor();

            services.AddTransient<IUserService, UserService>();
            services.AddTransient<IAuthService, AuthorizationService>();
            services.AddSingleton<IEmailService, EmailService>();
            services.AddScoped(typeof(IRepository<>), typeof(Repository<>));

            //Add authetication
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(o =>
            {
                var signingKey = Encoding.UTF8.GetBytes(Configuration["JWTSettings:SecretKey"]);
                var encryptionKey = Encoding.UTF8.GetBytes(Configuration["JWTSettings:EncryptionKey"]);

                o.IncludeErrorDetails = true;
                o.SaveToken = true;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuerSigningKey = true,

                    ValidIssuer = Configuration["JWTSettings:Issuer"],
                    ValidAudience = Configuration["JWTSettings:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(signingKey),
                    TokenDecryptionKey = new SymmetricSecurityKey(encryptionKey)
                };
            });

            services.AddControllers();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(options =>
            {
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] followed by your token.\r\n\r\nExample: \"Bearer AUTH_TOKEN_HERE\"",
                });
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] { }
                    }
                });
            });
        }

        public void Configure(WebApplication app, IWebHostEnvironment env)
        {
            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            SetupMapster();

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
        }

        private void SetupMapster()
        {
            TypeAdapterConfig<User, RegisterUser>.NewConfig()
                .TwoWays()
                .Map(dest => dest.DateOfBirth, src => src.DOB);
        }
    }
}
