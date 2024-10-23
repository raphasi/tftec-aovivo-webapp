﻿using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using CRM.Application.Interfaces;
using CRM.Application.Services;
using CRM.Domain.Interfaces;
using CRM.Infrastructure.Context;
using CRM.Infrastructure.Repositories;
using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using CRM.Domain.Entities;
using CRM.Application.Mappings;
using CRM.Infrastructure.Identity;
using CRM.Domain.Account;
using MediatR;

namespace CRM.CrossCutting.IoC
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            // Obter a string de conexão do arquivo de configuração
            string connectionString = configuration.GetConnectionString("DefaultConnection");

            // Configuração do DbContext
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));

            // Configuração do Identity
            services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Registro de Repositórios
            services.AddScoped<IActivityRepository, ActivityRepository>();
            services.AddScoped<ICustomerRepository, CustomerRepository>();
            services.AddScoped<IEventRepository, EventRepository>();
            services.AddScoped<ILeadRepository, LeadRepository>();
            services.AddScoped<INoteRepository, NoteRepository>();
            services.AddScoped<IOpportunityRepository, OpportunityRepository>();
            services.AddScoped<IOrderRepository, OrderRepository>();
            services.AddScoped<IOrderItemRepository, OrderItemRepository>();
            services.AddScoped<IPriceLevelRepository, PriceLevelRepository>();
            services.AddScoped<IProductRepository, ProductRepository>();
            services.AddScoped<IQuoteRepository, QuoteRepository>();

            // Registro de Serviços
            services.AddScoped<IActivityService, ActivityService>();
            services.AddScoped<ICustomerService, CustomerService>();
            services.AddScoped<IEventService, EventService>();
            services.AddScoped<ILeadService, LeadService>();
            services.AddScoped<INoteService, NoteService>();
            services.AddScoped<IOpportunityService, OpportunityService>();
            services.AddScoped<IOrderService, OrderService>();
            services.AddScoped<IOrderItemService, OrderItemService>();
            services.AddScoped<IPriceLevelService, PriceLevelService>();
            services.AddScoped<IProductService, ProductService>();
            services.AddScoped<IQuoteService, QuoteService>();
            services.AddScoped<IAuthenticate, AuthenticateService>();

            // Configuração do AutoMapper
            services.AddAutoMapper(typeof(DomainToDTOMappingProfile));

            var myhandlers = AppDomain.CurrentDomain.Load("CRM.Application");
            // Adicionar MediatR e registrar os handlers
            services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(myhandlers));


            return services;
        }
    }
}