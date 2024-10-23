﻿using CRM.Domain.Entities;
using CRM.WebApp.Site.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
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
        var user = GetUserInfo();
        return new T
        {
            CreatedOn = DateTime.Now,
            CreatedBy = new Guid(user.id), // ou obtenha o ID do usuário logado
            CreatedByName = user.userName, // ou obtenha o ID do usuário logado
            ModifiedOn = DateTime.Now,
            ModifiedBy = new Guid(user.id), // ou obtenha o ID do usuário logado
            ModifiedByName = user.userName, // ou obtenha o ID do usuário logado
            IsNew = true
        };
    }

    protected void UpdateEntity(T entity)
    {
        var user = GetUserInfo();
        entity.ModifiedOn = DateTime.Now;
        entity.ModifiedBy = new Guid(user.id); // ou obtenha o ID do usuário logado
        entity.ModifiedByName = user.userName; // ou obtenha o ID do usuário logado
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

    public async Task<IActionResult> GetCount([FromQuery] string query = null)
    {
        var client = _httpClientFactory.CreateClient("CRM.API");
        var response = await client.GetAsync($"/api/{_entityName}/count?query={query}");
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
        // Obtenha o token de acesso do ClaimsPrincipal do usuário autenticado
        return HttpContext.User.FindFirst("access_token")?.Value;
    }

    protected UserInfoViewModel GetUserInfo()
    {
        // Obtenha as informações do usuário autenticado a partir do ClaimsPrincipal
        var userId = HttpContext.User.FindFirst("userId")?.Value;
        var userName = HttpContext.User.FindFirst(ClaimTypes.Name)?.Value;

        return new UserInfoViewModel
        {
            id = userId,
            userName = userName
        };
    }

    protected static void PutTokenInHeaderAuthorization(string token, HttpClient client)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}