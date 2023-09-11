using coderush.Data;
using coderush.Models;
using coderush.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
               options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Get Identity Default Options
IConfigurationSection identityDefaultOptionsConfigurationSection = builder.Configuration.GetSection("IdentityDefaultOptions");

builder.Services.Configure<IdentityDefaultOptions>(identityDefaultOptionsConfigurationSection);

var identityDefaultOptions = identityDefaultOptionsConfigurationSection.Get<IdentityDefaultOptions>();
builder.Services.AddControllersWithViews();
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = identityDefaultOptions.PasswordRequireDigit;
    options.Password.RequiredLength = identityDefaultOptions.PasswordRequiredLength;
    options.Password.RequireNonAlphanumeric = identityDefaultOptions.PasswordRequireNonAlphanumeric;
    options.Password.RequireUppercase = identityDefaultOptions.PasswordRequireUppercase;
    options.Password.RequireLowercase = identityDefaultOptions.PasswordRequireLowercase;
    options.Password.RequiredUniqueChars = identityDefaultOptions.PasswordRequiredUniqueChars;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(identityDefaultOptions.LockoutDefaultLockoutTimeSpanInMinutes);
    options.Lockout.MaxFailedAccessAttempts = identityDefaultOptions.LockoutMaxFailedAccessAttempts;
    options.Lockout.AllowedForNewUsers = identityDefaultOptions.LockoutAllowedForNewUsers;

    // User settings
    options.User.RequireUniqueEmail = identityDefaultOptions.UserRequireUniqueEmail;

    // email confirmation require
    options.SignIn.RequireConfirmedEmail = identityDefaultOptions.SignInRequireConfirmedEmail;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    // Cookie settings
    options.Cookie.HttpOnly = identityDefaultOptions.CookieHttpOnly;
    //options.Cookie.Expiration = TimeSpan.FromDays(identityDefaultOptions.CookieExpiration);
    options.LoginPath = identityDefaultOptions.LoginPath; // If the LoginPath is not set here, ASP.NET Core will default to /Account/Login
    options.LogoutPath = identityDefaultOptions.LogoutPath; // If the LogoutPath is not set here, ASP.NET Core will default to /Account/Logout
    options.AccessDeniedPath = identityDefaultOptions.AccessDeniedPath; // If the AccessDeniedPath is not set here, ASP.NET Core will default to /Account/AccessDenied
    options.SlidingExpiration = identityDefaultOptions.SlidingExpiration;
});

// Get SendGrid configuration options
builder.Services.Configure<SendGridOptions>(builder.Configuration.GetSection("SendGridOptions"));

// Get SMTP configuration options
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("SmtpOptions"));

// Get Super Admin Default options
builder.Services.Configure<SuperAdminDefaultOptions>(builder.Configuration.GetSection("SuperAdminDefaultOptions"));

// Add email services.
builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.AddTransient<INumberSequence, coderush.Services.NumberSequence>();

builder.Services.AddTransient<IRoles, Roles>();

builder.Services.AddTransient<IFunctional, Functional>();

//builder.Services.AddMvc();
//.AddJsonOptions(options =>
//{
//    options.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
//    //pascal case json
//    options.ContractResolver = new DefaultContractResolver();

//});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=UserRole}/{action=UserProfile}/{id?}");


using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var functional = services.GetRequiredService<IFunctional>();

        DbInitializer.Initialize(context, functional).Wait();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}
app.Run();
