using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Identity.Web;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using CRM.Application.DTOs;
using Microsoft.Extensions.Caching.Memory;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Net.Http.Json;
using Newtonsoft.Json;

namespace CRM.CrossCutting.IoC
{
    public static class DependencyInjectionB2C
    {
        public static IServiceCollection AddInfrastructureB2C(this IServiceCollection services, IConfiguration configuration)
        {
            // Adiciona o HttpContextAccessor para acessar o contexto da requisição
            services.AddHttpContextAccessor();

            services.AddHttpClient("AuthService", client =>
            {
                client.BaseAddress = new Uri(configuration["AuthSettings:BaseUrl"]);
            });

            // Configuração do HttpClient
            services.AddHttpClient("CRM.API", client =>
            {
                client.BaseAddress = new Uri(configuration["ApiSettings:BaseUrl"]);
            });


            // Configura a autenticação
            ConfigureAuthentication(services, configuration);

            // Configura a autorização
            ConfigureAuthorization(services);

            // Habilita a exibição de PII para depuração
            IdentityModelEventSource.ShowPII = true;

            // Retorna os serviços configurados
            return services;
        }

        private static void ConfigureAuthentication(IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddMicrosoftIdentityWebApp(configuration.GetSection("AzureAdB2C"));

            services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = context =>
                    {
                        // Lê o token do cookie e injeta no contexto
                        var token = context.Properties.GetTokenValue("id_token");
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
            });

            // Adiciona tratamento de erros para autenticação
            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.SaveTokens = true; // Salva os tokens no cookie
                options.Events = new OpenIdConnectEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.Response.Redirect("Error"); // Redireciona para uma página de erro
                        context.HandleResponse(); // Impede o processamento padrão
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = async context =>
                    {
                        var accessToken = context.SecurityToken as JwtSecurityToken;
                        if (accessToken != null)
                        {
                            // Log ou manipulação adicional do token
                            Console.WriteLine("Access Token: " + accessToken.RawData);
                            // Adiciona o token como claim, se necessário
                            var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
                            claimsIdentity?.AddClaim(new Claim("access_token", accessToken.RawData));

                            var httpClientFactory = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>();
                            var syncResult = await SyncUserWithAuthService(accessToken.RawData, httpClientFactory, configuration);

                            if (syncResult != null)
                            {
                                UpdateUserClaims(claimsIdentity, syncResult, accessToken.RawData, httpClientFactory);
                            }

                        }
                        //return Task.CompletedTask;
                    }
                };
            });
        }
        private static void ConfigureAuthorization(IServiceCollection services)
        {
            // Configura a autorização
            services.AddAuthorization(options =>
            {
                // Cria uma política de autorização padrão que requer um usuário autenticado
                var commonPolicy = new AuthorizationPolicyBuilder(OpenIdConnectDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser() // Requer que o usuário esteja autenticado
                    .Build();

                // Adiciona a política de autorização "AzureAdB2C"
                options.AddPolicy("AzureAdB2C", commonPolicy);

                // Adiciona políticas de autorização específicas para "AdminOnly" e "UserOnly"
                // options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
                // options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
            });
        }

        private static async Task<UserInfoDTO> SyncUserWithAuthService(string accessToken, IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            var client = httpClientFactory.CreateClient("AuthService");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            try
            {
                var response = await client.PostAsync("api/Auth/SyncAzureB2cUser", null);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var options = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true,
                        Converters = { new JsonStringEnumConverter() }
                    };

                    var tokenResponse = System.Text.Json.JsonSerializer.Deserialize<TokenDTO>(content, options);

                    return tokenResponse?.UserInfo;
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
                return null;
            }
        }

        private static async void UpdateUserClaims(ClaimsIdentity identity, UserInfoDTO userInfo, string token, IHttpClientFactory httpClientFactory)
        {
            if (identity == null) return;

            var claimsToRemove = identity.Claims.Where(c =>
                c.Type == ClaimTypes.Name ||
                c.Type == ClaimTypes.Email ||
                c.Type == ClaimTypes.Role ||
                c.Type == "securityIdentifier" ||
                c.Type == "access_token" ||
                c.Type == "userId").ToList();

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
            else
            {
                //var client = httpClientFactory.CreateClient("CRM.API");

                //LeadDTO lead = new LeadDTO();
                //lead.FullName = userInfo.UserName;
                //lead.Email = userInfo.Email;
                //lead.Telephone = "5551999999999";
                //var responseLead = await client.PostAsJsonAsync("api/lead", lead);
                //responseLead.EnsureSuccessStatusCode();

                //if (responseLead.IsSuccessStatusCode)
                //{
                //    var leadId = await responseLead.Content.ReadAsStringAsync();
                //    LeadDTO leadIdResult = Newtonsoft.Json.JsonConvert.DeserializeObject<LeadDTO>(leadId);

                //    if (leadIdResult != null)
                //        identity.AddClaim(new Claim("leadId", leadIdResult.LeadID.ToString()));
                //}

                SyncCreateLead(httpClientFactory, userInfo, identity);
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

        private static void SyncCreateLead(IHttpClientFactory httpClientFactory, UserInfoDTO userInfo, ClaimsIdentity identity)
        {
            try
            {
                var client = httpClientFactory.CreateClient("CRM.API");

                LeadDTO lead = new LeadDTO
                {
                    FullName = userInfo.UserName,
                    Email = userInfo.Email,
                    Telephone = "5551999999999"
                };

                // Criar o conteúdo JSON
                var content = new StringContent(JsonConvert.SerializeObject(lead), Encoding.UTF8, "application/json");

                // Fazer a chamada POST síncrona
                var response = client.PostAsync("api/lead", content).GetAwaiter().GetResult();
                response.EnsureSuccessStatusCode();

                if (response.IsSuccessStatusCode)
                {
                    var leadId = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    LeadDTO leadIdResult = JsonConvert.DeserializeObject<LeadDTO>(leadId);

                    if (leadIdResult != null)
                    {
                        identity.AddClaim(new Claim("leadId", leadIdResult.LeadID.ToString()));
                    }
                }
            }
            catch (Exception ex)
            {
                // Log do erro
                Console.WriteLine($"Erro ao criar lead: {ex.Message}");
                // Você pode querer lançar a exceção novamente ou lidar com ela de outra forma
            }
        }
    }
}