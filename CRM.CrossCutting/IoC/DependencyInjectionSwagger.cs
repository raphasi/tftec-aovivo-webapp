using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;

namespace CRM.CrossCutting.IoC
{
    public static class DependencyInjectionSwagger
    {
        public static IServiceCollection AddInfrastructureSwagger(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "API", Version = "v1" });

                // Obtenha as configurações do Azure B2C
                var authorizationUrl = configuration["SwaggerAzure:AuthorizationUrl"];
                var tokenUrl = configuration["SwaggerAzure:TokenUrl"];
                var scope = configuration["SwaggerAzure:Scope"];

                // Verifique se as configurações não são nulas
                if (string.IsNullOrEmpty(authorizationUrl))
                    throw new ArgumentNullException(nameof(authorizationUrl), "Authorization URL cannot be null or empty.");
                if (string.IsNullOrEmpty(tokenUrl))
                    throw new ArgumentNullException(nameof(tokenUrl), "Token URL cannot be null or empty.");
                if (string.IsNullOrEmpty(scope))
                    throw new ArgumentNullException(nameof(scope), "Scope cannot be null or empty.");

                // Configuração de segurança
                c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
                {
                    Description = "Azure B2C Authorize",
                    Name = "Oauth2.0",
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        AuthorizationCode = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = new Uri(authorizationUrl),
                            TokenUrl = new Uri(tokenUrl),
                            Scopes = new Dictionary<string, string>
                            {
                                { scope, "Access API Azure B2C" }
                            }
                        }
                    }
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "oauth2"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header
                        },
                        new[] { scope }
                    }
                });

                // Adiciona outros filtros, se necessário
                // c.OperationFilter<YourCustomFilter>();

                // Configurações adicionais
                // c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, "YourApi.xml"));
            });

            return services;
        }
    }
}