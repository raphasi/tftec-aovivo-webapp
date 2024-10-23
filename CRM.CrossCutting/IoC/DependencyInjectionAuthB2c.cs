using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace CRM.CrossCutting.IoC
{
    public static class DependencyInjectionAuthB2c
    {
        public static IServiceCollection DependencyInjectionAuth(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options => {
                options.DefaultScheme = "AzureAdorAzureB2C";
                options.DefaultChallengeScheme = "AzureAdorAzureB2C";
            })
            .AddJwtBearer("AzureAd", options =>
            {
                options.Authority = configuration["AzureAd:Authority"];
                options.Audience = configuration["AzureAd:Audience"];
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuers = new[]
                    {
                        configuration["AzureAd:Issuer"],
                        $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0"
                    },
                    ValidAudience = configuration["AzureAd:Audience"],
                    IssuerValidator = (issuer, securityToken, validationParameters) =>
                    {
                        if (validationParameters.ValidIssuers != null &&
                            validationParameters.ValidIssuers.Any(vi => issuer.StartsWith(vi)))
                        {
                            return issuer;
                        }
                        throw new SecurityTokenInvalidIssuerException("The issuer is not valid.");
                    }
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine($"OnAuthenticationFailed: {context.Exception.Message}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        Console.WriteLine($"OnTokenValidated: {context.SecurityToken}");
                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        Console.WriteLine($"OnChallenge: {context.Error}, {context.ErrorDescription}");
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
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine($"B2C OnAuthenticationFailed: {context.Exception.Message}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        Console.WriteLine($"B2C OnTokenValidated: {context.SecurityToken}");
                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        Console.WriteLine($"B2C OnChallenge: {context.Error}, {context.ErrorDescription}");
                        return Task.CompletedTask;
                    }
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
                            var jwtToken = jwtHandler.ReadJwtToken(token);
                            var issuer = jwtToken.Issuer;
                            Console.WriteLine($"Token Issuer: {issuer}");
                            if (issuer == configuration["AzureB2C:Issuer"])
                                return "AzureB2C";
                        }
                    }
                    return "AzureAd";
                };
            });

            services.AddAuthorization(options =>
            {
                var commonPolicy = new AuthorizationPolicyBuilder("AzureAd", "AzureB2C")
                    .RequireAuthenticatedUser()
                    .RequireClaim("scope", "access_as_user")
                    .Build();
                options.AddPolicy("AzureAdorAzureB2CPolicy", commonPolicy);
            });

            return services;
        }
    }
}