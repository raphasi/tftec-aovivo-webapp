using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;

namespace CRM.CrossCutting.IoC
{
    public static class DependencyInjectionAuth
    {
        private class AuthLogger { }

        public static IServiceCollection AddInfrastructureAuth(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "AzureAdorAzureB2C";
                options.DefaultChallengeScheme = "AzureAdorAzureB2C";
            })
            .AddJwtBearer("AzureAd", options =>
            {
                options.Authority = $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0";
                options.Audience = configuration["AzureAd:Audience"];
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuers = new[]
                    {
                        $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0",
                        $"https://sts.windows.net/{configuration["AzureAd:TenantId"]}/"
                    },
                    ValidAudiences = new[]
                    {
                        configuration["AzureAd:Audience"],
                        $"api://{configuration["AzureAd:Audience"]}"
                    },
                    NameClaimType = "name",
                    RoleClaimType = "roles"
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<AuthLogger>>();
                        logger.LogError($"Authentication failed: {context.Exception.Message}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<AuthLogger>>();
                        logger.LogInformation("Token validated successfully");
                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<AuthLogger>>();
                        logger.LogWarning($"OnChallenge: {context.Error}, {context.ErrorDescription}");
                        return Task.CompletedTask;
                    }
                };
            })
            .AddJwtBearer("AzureB2C", options =>
            {
                options.Authority = configuration["AzureB2C:Authority"];
                options.Audience = configuration["AzureB2C:Audience"];
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = configuration["AzureB2C:Issuer"],
                    ValidAudience = configuration["AzureB2C:Audience"]
                };
            })
            .AddPolicyScheme("AzureAdorAzureB2C", "AzureAdorAzureB2C", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    string authorization = context.Request.Headers[HeaderNames.Authorization];
                    if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                    {
                        var token = authorization.Substring("Bearer ".Length).Trim();
                        var jwtHandler = new JwtSecurityTokenHandler();
                        if (jwtHandler.CanReadToken(token))
                        {
                            var jwt = jwtHandler.ReadJwtToken(token);
                            var issuer = jwt.Issuer;
                            if (issuer == configuration["AzureB2C:Issuer"])
                                return "AzureB2C";
                        }
                    }
                    return "AzureAd";
                };
            });

            services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new AuthorizationPolicyBuilder("AzureAdorAzureB2C")
                    .RequireAuthenticatedUser()
                    .Build();

                options.AddPolicy("AdminOnly", policy =>
                    policy.RequireRole("Admin").AddAuthenticationSchemes("AzureAdorAzureB2C"));

                options.AddPolicy("UserOnly", policy =>
                    policy.RequireRole("User").AddAuthenticationSchemes("AzureAdorAzureB2C"));
            });

            return services;
        }
    }
}