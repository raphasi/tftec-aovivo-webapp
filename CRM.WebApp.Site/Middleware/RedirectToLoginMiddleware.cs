using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

public class RedirectToLoginMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RedirectToLoginMiddleware(RequestDelegate next, IHttpContextAccessor httpContextAccessor)
    {
        _next = next;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var accessToken = GetAccessToken(context);

        // Verifica se a rota exige autenticação
        var endpoint = context.GetEndpoint();
        var authorizeAttribute = endpoint?.Metadata.GetMetadata<AuthorizeAttribute>();

        if (authorizeAttribute != null && string.IsNullOrEmpty(accessToken))
        {
            // Redireciona para a página de login do Azure AD
            await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);
            return;
        }

        await _next(context);
    }

    private string GetAccessToken(HttpContext context)
    {
        // Obtenha o token de acesso do ClaimsPrincipal do usuário autenticado
        return _httpContextAccessor.HttpContext?.User.FindFirst("access_token")?.Value;
    }
}