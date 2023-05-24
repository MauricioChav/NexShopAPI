using NexShopAPI.Application.Functionality.Configuration;
using NexShopAPI.BusinessLogic.IRepositories;
using NexShopAPI.BusinessLogic.Repositories;
using NexShopAPI.BusinessLogic.Configuration;
using NexShopAPI.DataAccess.IOperations;
using NexShopAPI.DataAccess.Operations;
using Microsoft.Extensions.DependencyInjection;
using AutoMapper;
using NexShopAPI.Middleware;
using NexShopAPI.DataAccess;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using NexShopAPI.DataAccess.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

//Entity Framework DBContext
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDBContext>(options =>
{
    options.UseSqlServer(connectionString);
});

builder.Services.AddIdentityCore<ApplicationUser>()
    .AddRoles<IdentityRole>()
    //.AddTokenProvider<DataProtectorTokenProvider<ApplicationUser>>("NexShopAPI")
    .AddEntityFrameworkStores<ApplicationDBContext>();
    //.AddDefaultTokenProviders();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
    {
        Description = @"JWT Authorization header using the Bearer scheme.
                        Enter 'Bearer' [space] and then your token in the text input below.
                        Example: 'Bearer 12345abcdef'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = JwtBearerDefaults.AuthenticationScheme
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = JwtBearerDefaults.AuthenticationScheme
                },
                Scheme = "Oauth2",
                Name = JwtBearerDefaults.AuthenticationScheme,
                In = ParameterLocation.Header
            },
            new List<string>()
        }
    });
});

//Configure Middleware
builder.Services.AddTransient<GlobalExceptionHandlerMiddleware>();

//Opearations Dependency Implementation
builder.Services.AddScoped<IClientOperation, ClientOperations>();
builder.Services.AddScoped<IAddressOperation, AddressOperations>();
builder.Services.AddScoped<IAuthManager, AuthManager>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
        ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
        ValidAudience = builder.Configuration["JwtSettings:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Key"]))
    };
});

//Mapper
builder.Services.AddAutoMapper(typeof(AutoMapperConfig));

//Repositories
builder.Services.AddScoped<IClientsRepository>(sp =>
{
    var operations = sp.GetService<IClientOperation>();
    var mapper = sp.GetService<IMapper>();
    return new ClientRepository(operations, mapper);
});

builder.Services.AddScoped<IAddressRepository>(sp =>
{
    var addressOperations = sp.GetService<IAddressOperation>();
    var clientOperations = sp.GetService<IClientOperation>();
    var mapper = sp.GetService<IMapper>();
    return new AddressRepository(addressOperations, clientOperations, mapper);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<GlobalExceptionHandlerMiddleware>();

app.MapControllers();

app.Run();
