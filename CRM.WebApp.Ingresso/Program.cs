using CRM.CrossCutting.IoC;
using CRM.WebApp.Ingresso.Middleware;
using CRM.WebApp.Ingresso.Models;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Configuração do HttpClient
builder.Services.AddHttpClient("CRM.API", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ApiSettings:BaseUrl"]);
});

builder.Services.AddHttpClient("Auth.API", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["AuthSettings:BaseUrl"]);
});

// Configuração de cache e sessões
builder.Services.AddDistributedMemoryCache(); // Necessário para armazenar sessões na memória
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromDays(1); // Tempo de expiração da sessão
    options.Cookie.HttpOnly = true; // Torna o cookie de sessão acessível apenas via HTTP
    options.Cookie.IsEssential = true; // Necessário para conformidade com GDPR
});

// Configuração do modelo de imagens
builder.Services.Configure<ConfigurationImageViewModel>(options =>
{
    options.NomePastaImagensProdutos = builder.Configuration["ConfigurationPastaImagens:NomePastaImagensProdutos"];
});

// Configuração da autenticação e autorização com Azure AD B2C
builder.Services.AddInfrastructureB2C(builder.Configuration);

// Adiciona suporte a controladores e views
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error"); // Tratamento de erros
    app.UseHsts(); // HSTS para segurança
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession(); // Habilita sessões

app.UseAuthentication(); // Middleware de autenticação
app.UseRedirectToLogin(); // Middleware personalizado para redirecionamento
app.UseAuthorization(); // Middleware de autorização

// Configura a localização
var localizationOptions = app.Services.GetService<IOptions<RequestLocalizationOptions>>().Value;
app.UseRequestLocalization(localizationOptions);

// Configuração das rotas
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Event}/{action=List}/{id?}");
});

app.Run();