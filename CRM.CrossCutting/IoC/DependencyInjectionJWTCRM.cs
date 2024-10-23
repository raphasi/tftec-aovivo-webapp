using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Globalization;
using System.Text;

namespace CRM.CrossCutting.IoC
{
    public static class DependencyInjectionJWTCRM
    {
        public static IServiceCollection AddInfrastructureJWTCRM(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0";
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = "https://login.microsoftonline.com/{TenantId}/v2.0",
                        ValidAudience = configuration["AzureAd:ClientId"]
                    };
                });

            return services;
        }
    }
}