using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace CRM.WebApp.Site.Middleware;

public static class RedirectToLoginMiddlewareExtensions
{
    public static IApplicationBuilder UseRedirectToLogin(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RedirectToLoginMiddleware>();
    }
}