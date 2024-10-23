using CRM.CrossCutting.IoC;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Adiciona serviços de infraestrutura
builder.Services.AddInfrastructureAPI(builder.Configuration);
builder.Services.AddInfrastructureAuth(builder.Configuration);
builder.Services.AddInfrastructureSwagger(builder.Configuration);

// Adiciona serviços de controle e configurações JSON
builder.Services.AddControllers().AddJsonOptions(x =>
    x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);

var app = builder.Build();

// Configura o pipeline de requisição HTTP
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.OAuthClientId(builder.Configuration["SwaggerAzureAd:ClientId"]);
    c.OAuthUsePkce();
    c.OAuthScopeSeparator(" ");
});

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication(); // Adiciona middleware de autenticação
app.UseAuthorization();  // Adiciona middleware de autorização

app.MapControllers();

app.Run();