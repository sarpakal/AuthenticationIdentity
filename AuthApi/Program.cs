using System.Text;
using System.Threading.RateLimiting;
using AuthApi.Data;
using AuthApi.Entities;
using AuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// ── Database ────────────────────────────────────────────────────────────────
var dbPath = Path.Combine(builder.Environment.ContentRootPath, "authapi.db");

Console.WriteLine($"DB PATH: {dbPath}");

builder.Services.AddDbContext<AppDbContext>(opts =>
    opts.UseSqlite($"Data Source={dbPath}"));
//opts.UseSqlite(builder.Configuration.GetConnectionString("SqliteDefaultConnection")));
    //opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
// Swap to UseSqlite(...) or UseNpgsql(...) as needed

// ── Identity ────────────────────────────────────────────────────────────────
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(opts =>
{
    opts.User.RequireUniqueEmail = false;
    opts.Password.RequireDigit = false;
    opts.Password.RequireNonAlphanumeric = false;
    opts.Password.RequiredLength = 0;
    opts.Password.RequireUppercase = false;
    opts.Password.RequireLowercase = false;

    opts.Lockout.MaxFailedAccessAttempts = 10;
    opts.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// ── JWT Authentication ───────────────────────────────────────────────────────
var jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("Jwt:Key is not configured.");

builder.Services.AddAuthentication(opts =>
{
    opts.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opts.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(opts =>
{
    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero,
    };
});

// ── Authorization Policies ───────────────────────────────────────────────────
builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
    opts.AddPolicy("UserOrAdmin", p => p.RequireRole("User", "Admin"));
});

// ── Rate Limiting ────────────────────────────────────────────────────────────
builder.Services.AddRateLimiter(opts =>
{
    opts.AddFixedWindowLimiter("auth", limiter =>
    {
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.PermitLimit = 10;
        limiter.QueueLimit = 0;
        limiter.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });

    opts.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// ── App Services ─────────────────────────────────────────────────────────────
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<ISmsService, ConsoleSmsService>(); // Swap to TwilioSmsService in prod

// ── OpenAPI (.NET 10 native) ─────────────────────────────────────────────────
// Uses Microsoft.AspNetCore.OpenApi — no Swashbuckle needed.
// Visit /openapi/v1.json for the raw spec.
// Use Scalar (or any OpenAPI UI) to browse it in dev.
builder.Services.AddEndpointsApiExplorer(); // <-- needed for OpenAPI discovery

builder.Services.AddOpenApi(options => // <-- generates /openapi/v1.json
{
    options.AddDocumentTransformer((document, context, ct) =>
    {
        document.Info.Title = "AuthApi";
        document.Info.Version = "v1";

        // Register Bearer JWT security scheme using the concrete OpenApiSecurityScheme type
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["Bearer"] =
            new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Enter your JWT access token.",
            };

        return Task.CompletedTask;
    });
});

builder.Services.AddControllers();

var app = builder.Build();

// ✅ THIS PART IS MISSING (or too late in your pipeline)
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    Console.WriteLine("Applying migrations...");
    var db = services.GetRequiredService<AppDbContext>();
    db.Database.Migrate();

    // Optional: seed roles
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    if (!await roleManager.RoleExistsAsync("Admin"))
    {
        await roleManager.CreateAsync(new IdentityRole("Admin"));
    }
}


// ── Seed roles ────────────────────────────────────────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "Admin", "User" })
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }
}

if (app.Environment.IsDevelopment())
{
    // Serves the OpenAPI JSON spec at /openapi/v1.json
    app.MapOpenApi(); // <-- serves the generated OpenAPI spec (exposes the document to clients)

    // Optional: lightweight Swagger UI via Scalar
    // Install: dotnet add package Scalar.AspNetCore
    app.MapScalarApiReference();
}

//app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
