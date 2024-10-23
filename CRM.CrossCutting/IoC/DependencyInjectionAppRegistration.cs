using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace CRM.CrossCutting.IoC;

public static class DependencyInjectionAppRegistration
{
    public static IServiceCollection AddInfrastructureAzure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
                .AddCookie(options =>
                {
                    options.LoginPath = "/Account/Login";
                    options.AccessDeniedPath = "/Account/AccessDenied";
                    options.Events = new CookieAuthenticationEvents
                    {
                        OnValidatePrincipal = context =>
                        {
                            // Lê o token do cookie e injeta no contexto
                            var token = context.Properties.GetTokenValue("access_token");
                            if (!string.IsNullOrEmpty(token))
                            {
                                context.Principal.AddIdentity(new ClaimsIdentity(new[]
                                {
                            new Claim("access_token", token)
                                }));
                            }
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.Authority = $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0";
                    options.ClientId = configuration["AzureAd:ClientId"];
                    options.CallbackPath = "/signin-oidc";
                    options.ResponseType = "code";
                    options.ResponseMode = "query";
                    options.ClientSecret = configuration["AzureAd:ClientSecret"];
                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0",
                        ValidAudience = configuration["AzureAd:ClientId"]
                    };
                });

        services.AddAuthorization(options =>
        {
            var commonPolicy = new AuthorizationPolicyBuilder(OpenIdConnectDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser()
                .RequireRole("Admin", "User", "Client")
                .Build();

            options.AddPolicy("AzureAD", commonPolicy);
            options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
            options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
        });

        return services;
    }
}