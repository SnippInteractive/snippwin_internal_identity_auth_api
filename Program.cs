using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using SnippInternalIdentity.AuthApi.Services;
using SnippInternalIdentity.Domain.Interfaces;
using SnippInternalIdentity.Infrastructure.Data.Contexts;
using SnippInternalIdentity.Infrastructure.Repositories;
using SnippInternalIdentity.Infrastructure.Services;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Database Configuration
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Unit of Work Registration
builder.Services.AddScoped<IUnitOfWork>(provider => provider.GetRequiredService<ApplicationDbContext>());

// Repository Registration
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();
builder.Services.AddScoped<IPermissionRepository, PermissionRepository>();
builder.Services.AddScoped<IAuditLogRepository, AuditLogRepository>();

// Service Registration
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();
builder.Services.AddScoped<IPasswordHashingService, PasswordHashingService>();
builder.Services.AddScoped<AuthenticationService>();

// CORS Configuration
var corsOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("ApiCorsPolicy", policy =>
    {
        policy.WithOrigins(corsOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// Rate Limiting Configuration (simple in-memory implementation)
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<Dictionary<string, (DateTime LastRequest, int RequestCount)>>();

// API Documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Snipp Internal Identity Authentication API",
        Version = "v1",
        Description = "Centralized authentication validation API for Snipp Interactive internal applications",
        Contact = new OpenApiContact
        {
            Name = "Snipp Interactive Development Team",
            Email = "dev@snippinteractive.com"
        }
    });

    // Add Basic Authentication scheme to Swagger
    c.AddSecurityDefinition("Basic", new OpenApiSecurityScheme
    {
        Description = "Basic Authorization header using the Bearer scheme. Example: \"Authorization: Basic {base64 encoded username:password}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "basic"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Basic"
                }
            },
            Array.Empty<string>()
        }
    });

    // Include XML comments for better API documentation
    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFilename);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

// Logging Configuration
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Snipp Internal Identity Auth API v1");
        c.RoutePrefix = string.Empty; // Make Swagger UI available at root
        c.DocumentTitle = "Snipp Internal Identity Auth API";
    });
}

// Security Headers Middleware
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";
    
    if (!app.Environment.IsDevelopment())
    {
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    }
    
    await next();
});

// Simple Rate Limiting Middleware
app.Use(async (context, next) =>
{
    var rateLimitEnabled = builder.Configuration.GetValue<bool>("RateLimit:Enabled", true);
    if (!rateLimitEnabled)
    {
        await next();
        return;
    }

    var maxRequests = builder.Configuration.GetValue<int>("RateLimit:MaxRequests", 100);
    var windowSizeMinutes = builder.Configuration.GetValue<int>("RateLimit:WindowSizeMinutes", 15);
    
    var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var rateLimitDict = app.Services.GetRequiredService<Dictionary<string, (DateTime LastRequest, int RequestCount)>>();
    
    var now = DateTime.UtcNow;
    var windowStart = now.AddMinutes(-windowSizeMinutes);
    
    bool shouldBlock = false;
    
    lock (rateLimitDict)
    {
        if (rateLimitDict.TryGetValue(clientIp, out var entry))
        {
            if (entry.LastRequest > windowStart)
            {
                if (entry.RequestCount >= maxRequests)
                {
                    shouldBlock = true;
                }
                else
                {
                    rateLimitDict[clientIp] = (now, entry.RequestCount + 1);
                }
            }
            else
            {
                // Window has expired, reset counter
                rateLimitDict[clientIp] = (now, 1);
            }
        }
        else
        {
            // First request from this IP
            rateLimitDict[clientIp] = (now, 1);
        }
    }
    
    if (shouldBlock)
    {
        context.Response.StatusCode = 429; // Too Many Requests
        await context.Response.WriteAsync("Rate limit exceeded. Please try again later.");
        return;
    }
    
    await next();
});

app.UseHttpsRedirection();

app.UseCors("ApiCorsPolicy");

app.UseAuthorization();

app.MapControllers();

// Ensure database is created and seeded
try
{
    using var scope = app.Services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    
    // Ensure database exists
    await context.Database.EnsureCreatedAsync();
    
    app.Logger.LogInformation("Database connection verified successfully");
}
catch (Exception ex)
{
    app.Logger.LogError(ex, "Failed to connect to database on startup");
    throw;
}

app.Logger.LogInformation("Snipp Internal Identity Authentication API starting up...");
app.Logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
app.Logger.LogInformation("CORS Origins: {Origins}", string.Join(", ", corsOrigins));

app.Run();