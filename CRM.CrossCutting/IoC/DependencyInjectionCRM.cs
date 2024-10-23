using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using CRM.Application.DTOs;
using System.Security.Claims;
using System.Linq;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace CRM.CrossCutting.IoC;

public static class DependencyInjectionCRM
{
    public static IServiceCollection AddInfrastructureCRM(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();

        services.AddHttpClient("AuthService", client =>
        {
            client.BaseAddress = new Uri(configuration["AuthSettings:BaseUrl"]);
        });

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = OpenIdConnectDefaults.AuthenticationScheme;
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/Account/Login";
            options.AccessDeniedPath = "/Account/AccessDenied";
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.None;
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
            options.ClientSecret = configuration["AzureAd:ClientSecret"];
            options.ResponseType = "code";
            options.ResponseMode = "query";
            options.CallbackPath = "/signin-oidc";
            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;
            options.UseTokenLifetime = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = $"https://login.microsoftonline.com/{configuration["AzureAd:TenantId"]}/v2.0",
                ValidAudience = configuration["AzureAd:ClientId"],
                RoleClaimType = "roles",
                NameClaimType = "name"
            };
            options.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = async context =>
                {
                    var accessToken = context.TokenEndpointResponse.AccessToken;

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        var httpClientFactory = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>();
                        var syncResult = await SyncUserWithAuthService(accessToken, httpClientFactory, configuration);

                        if (syncResult != null)
                        {
                            var identity = (ClaimsIdentity)context.Principal.Identity;
                            UpdateUserClaims(identity, syncResult, accessToken);
                        }
                    }
                },
                OnRedirectToIdentityProvider = context =>
                {
                    if (context.HttpContext.User.Identity.IsAuthenticated)
                    {
                        context.HandleResponse();
                        return Task.CompletedTask;
                    }
                    context.ProtocolMessage.Prompt = "select_account";
                    return Task.CompletedTask;
                }
            };
            options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.CorrelationCookie.SameSite = SameSiteMode.None;
        });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("AzureAD", policy => policy.RequireAuthenticatedUser());
            options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
            options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
        });

        return services;
    }

    private static async Task<UserInfoDTO> SyncUserWithAuthService(string accessToken, IHttpClientFactory httpClientFactory, IConfiguration configuration)
    {
        var client = httpClientFactory.CreateClient("AuthService");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        try
        {
            var response = await client.PostAsync("api/Auth/SyncAzureAdUser", null);
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"SyncUserWithAuthService response content: {content}");

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    Converters = { new JsonStringEnumConverter() }
                };

                var tokenResponse = JsonSerializer.Deserialize<TokenDTO>(content, options);

                if (tokenResponse == null || tokenResponse.UserInfo == null)
                {
                    Console.WriteLine("Error: Failed to deserialize TokenResponse or UserInfo is null");
                    return null;
                }

                var syncResult = tokenResponse.UserInfo;

                if (string.IsNullOrEmpty(syncResult.Email))
                {
                    Console.WriteLine("Warning: Deserialized UserInfoDTO has null or empty Email");
                }

                return syncResult;
            }

            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Failed to sync user. Status code: {response.StatusCode}, Content: {errorContent}");
                return null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception occurred while syncing user: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            return null;
        }
    }

    private static void UpdateUserClaims(ClaimsIdentity identity, UserInfoDTO userInfo, string token)
    {
        var claimsToRemove = identity.Claims.Where(c =>
            c.Type == ClaimTypes.Name ||
            c.Type == ClaimTypes.Email ||
            c.Type == ClaimTypes.Role ||
            c.Type == "leadId" ||
            c.Type == "securityIdentifier").ToList();

        foreach (var claim in claimsToRemove)
        {
            identity.RemoveClaim(claim);
        }

        identity.AddClaim(new Claim(ClaimTypes.Name, userInfo.UserName));
        identity.AddClaim(new Claim(ClaimTypes.Email, userInfo.Email));
        identity.AddClaim(new Claim("access_token", token));
        identity.AddClaim(new Claim("userId", userInfo.Id));

        if (userInfo.LeadID.HasValue)
        {
            identity.AddClaim(new Claim("leadId", userInfo.LeadID.Value.ToString()));
        }

        if (!string.IsNullOrEmpty(userInfo.SecurityIdentifier))
        {
            identity.AddClaim(new Claim("securityIdentifier", userInfo.SecurityIdentifier));
        }

        if (userInfo.Roles != null)
        {
            foreach (var role in userInfo.Roles)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
            }
        }
    }
}