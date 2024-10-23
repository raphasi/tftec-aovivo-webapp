﻿using CRM.Domain.Entities;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using CRM.WebApp.Ingresso.Models;
using System.Net.Http.Headers;
using CRM.Application.DTOs;
using System.Security.Claims;

public abstract class BaseController<T, TViewModel> : Controller where T : EntityBase, new()
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _entityName;

    protected BaseController(IHttpClientFactory httpClientFactory, string entityName)
    {
        _httpClientFactory = httpClientFactory;
        _entityName = entityName;
    }

    protected T InitializeEntity()
    {
        return new T
        {
            CreatedOn = DateTime.Now,
            CreatedBy = Guid.NewGuid(), // ou obtenha o ID do usuário logado
            ModifiedOn = DateTime.Now,
            ModifiedBy = Guid.NewGuid(), // ou obtenha o ID do usuário logado
            IsNew = true
        };
    }

    protected void UpdateEntity(T entity)
    {
        entity.ModifiedOn = DateTime.Now;
        entity.ModifiedBy = Guid.NewGuid(); // ou obtenha o ID do usuário logado
        entity.IsNew = false;
    }

    public async Task<IActionResult> Search([FromQuery] string query = null)
    {
        var client = _httpClientFactory.CreateClient("CRM.API");
        var response = await client.GetAsync($"/api/{_entityName}/search?query={query}");
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        var entities = JsonConvert.DeserializeObject<IEnumerable<TViewModel>>(content);

        return Ok(entities);
    }

    public async Task<IActionResult> GetById(string id)
    {
        var client = _httpClientFactory.CreateClient("CRM.API");
        var response = await client.GetAsync($"api/{_entityName}/{id}");
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        var entities = JsonConvert.DeserializeObject<TViewModel>(content);

        return Ok(entities);
    }

    protected string GetAccessToken()
    {
        //return HttpContext.Session.GetString("access_token");
        return HttpContext.User.FindFirst("access_token")?.Value;
    }

    protected UserInfoViewModel GetUserInfo()
    {
        // Obtenha as informações do usuário autenticado a partir do ClaimsPrincipal
        var userId = HttpContext.User.FindFirst("userId")?.Value;
        var leadId = HttpContext.User.FindFirst("leadId")?.Value;
        var userName = HttpContext.User.FindFirst(ClaimTypes.Name)?.Value;

        return new UserInfoViewModel
        {
            id = userId,
            leadID = new Guid(leadId),
            userName = userName
        };
    }

    protected static void PutTokenInHeaderAuthorization(string token, HttpClient client)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }


}

public static class SessionExtensions
{
    public static void SetObjectAsJson(this ISession session, string key, object value)
    {
        session.SetString(key, JsonConvert.SerializeObject(value));
    }

    public static T GetObjectFromJson<T>(this ISession session, string key)
    {
        var value = session.GetString(key);
        return value == null ? default(T) : JsonConvert.DeserializeObject<T>(value);
    }
}