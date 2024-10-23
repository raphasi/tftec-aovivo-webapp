using Microsoft.AspNetCore.Authorization;

public class RedirectToLoginMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RedirectToLoginMiddleware> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public RedirectToLoginMiddleware(RequestDelegate next, ILogger<RedirectToLoginMiddleware> logger, IHttpContextAccessor httpContextAccessor)
    {
        _next = next;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Verifica se a rota exige autenticação
            var accessToken = GetAccessToken(context);
            var endpoint = context.GetEndpoint();
            var authorizeAttribute = endpoint?.Metadata.GetMetadata<AuthorizeAttribute>();

            if (authorizeAttribute != null && !context.User.Identity.IsAuthenticated)
            {
                _logger.LogInformation("Usuário não autenticado. Redirecionando para a página de login.");
                context.Response.Redirect($"/Account/Login?ReturnUrl={context.Request.Path}");
                return;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao processar o middleware de redirecionamento.");
            throw; // Re-throw a exception para que outros middlewares possam lidar com isso
        }

        await _next(context);
    }

    private string GetAccessToken(HttpContext context)
    {
        // Obtenha o token de acesso do ClaimsPrincipal do usuário autenticado
        return _httpContextAccessor.HttpContext?.User.FindFirst("access_token")?.Value;
    }
}