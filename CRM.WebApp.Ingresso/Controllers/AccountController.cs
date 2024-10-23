using CRM.WebApp.Ingresso.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace CRM.WebApp.Ingresso.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> _logger;

        public AccountController(ILogger<AccountController> logger)
        {
            _logger = logger;
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ProducesResponseType(201)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // Lógica de registro (se necessário)
            // Certifique-se de que a API de registro está funcionando corretamente
            return RedirectToAction("Login"); // Redireciona para a página de login após o registro
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public IActionResult Login(LoginViewModel model, string returnUrl = null)
        {
            // Inicia o processo de autenticação
            var redirectUrl = Url.Action("List", "Event"); // URL de redirecionamento após login
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpPost]
        public IActionResult Logout()
        {
            // Limpa o cookie de autenticação
            HttpContext.Response.Cookies.Delete(".AspNetCore.Cookies");
            return SignOut(new AuthenticationProperties { RedirectUri = Url.Action("Index", "Home") },
                           CookieAuthenticationDefaults.AuthenticationScheme,
                           OpenIdConnectDefaults.AuthenticationScheme);
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}