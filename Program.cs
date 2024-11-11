using Azure.Identity;
using System.Text.Json;
using Azure.Security.KeyVault.Secrets;
using DataTrust.Data;
using DataTrust.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Logging configuration before services are locked
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug); // For detailed logging

// URLs for the two separate Azure Key Vaults
var dbKeyVaultUrl = "https://database-application.vault.azure.net/"; // Vault for database connection
var googleAuthKeyVaultUrl = "https://googleauthapp.vault.azure.net/"; // Vault for Google OAuth
var facebookAuthKeyVaultUrl = "https://googleauthapp.vault.azure.net/"; // Vault for Facebook OAuth (updated URL)

// Create SecretClient for each Vault and fetch sensitive values from respective Key Vaults
var dbSecretClient = new SecretClient(new Uri(dbKeyVaultUrl), new DefaultAzureCredential());
var googleAuthSecretClient = new SecretClient(new Uri(googleAuthKeyVaultUrl), new DefaultAzureCredential());
var facebookAuthSecretClient = new SecretClient(new Uri(facebookAuthKeyVaultUrl), new DefaultAzureCredential());

string dbConnectionString, googleClientId, googleClientSecret, facebookAppId, facebookAppSecret;

try
{
    dbConnectionString = dbSecretClient.GetSecret("SqlConnectionNew").Value.Value;
    googleClientId = googleAuthSecretClient.GetSecret("ClientId").Value.Value;
    googleClientSecret = googleAuthSecretClient.GetSecret("ClientSecret").Value.Value;
    facebookAppId = facebookAuthSecretClient.GetSecret("AppId").Value.Value;
    facebookAppSecret = facebookAuthSecretClient.GetSecret("AppSecret").Value.Value;
}
catch (Exception ex)
{
    Console.WriteLine($"Error fetching secrets: {ex.Message}");
    throw;
}

// Add session support
builder.Services.AddDistributedMemoryCache();  // Add memory cache for session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);  // Set session timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add authentication and cookie handling
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "Google";  // Default to Google
})
.AddCookie(options =>
{
    // Cookie configuration
    options.Events.OnValidatePrincipal = async context =>
    {
        if (context.Properties.Items.ContainsKey("Processed"))
        {
            Console.WriteLine("User claims already processed for this session.");
            return;
        }
        context.Properties.Items["Processed"] = "true";

        var serviceProvider = context.HttpContext.RequestServices;
        using var db = new AppDbContext(serviceProvider.GetRequiredService<DbContextOptions<AppDbContext>>());

        var subject = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        var issuer = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Issuer;

        var name = context.Principal?.FindFirst("name")?.Value;
        var givenName = context.Principal?.FindFirst(ClaimTypes.GivenName)?.Value;
        var surname = context.Principal?.FindFirst(ClaimTypes.Surname)?.Value;

        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(surname))
        {
            name = $"{givenName} {surname}";
        }

        name ??= "Unknown User";

        if (subject == null || issuer == null)
        {
            Console.WriteLine("Missing required claims.");
            return;
        }

        var account = db.Accounts.FirstOrDefault(p => p.OpenIDIssuer == issuer && p.OpenIDSubject == subject);
        var email = context.Principal?.FindFirstValue(ClaimTypes.Email);

        if (account == null)
        {
            account = new Account
            {
                OpenIDIssuer = issuer,
                OpenIDSubject = subject,
                Name = name,
                Email = email
            };
            db.Accounts.Add(account);
        }
        else if (account.Name != name || account.Email != email)
        {
            account.Name = name;
            account.Email = email;
        }

        try
        {
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Database error: " + ex.Message);
        }
    };
})
.AddOpenIdConnect("Google", options =>
{
    options.Authority = "https://accounts.google.com";
    options.ClientId = googleClientId;
    options.ClientSecret = googleClientSecret;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.CallbackPath = "/signin-oidc-google";
    options.SignedOutRedirectUri = "/logout-success";
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.MetadataAddress = "https://accounts.google.com/.well-known/openid-configuration";

    // Force the user to select an account on each login
    options.Events.OnRedirectToIdentityProvider = context =>
    {
        context.ProtocolMessage.SetParameter("prompt", "select_account");
        return Task.CompletedTask;
    };
})
.AddFacebook(options =>
{
    options.AppId = facebookAppId;
    options.AppSecret = facebookAppSecret;
    options.CallbackPath = "/signin-facebook"; // Facebook's redirect URI after login
    options.Scope.Add("email");
    options.Scope.Add("public_profile");
    options.SaveTokens = true;
    options.Fields.Add("email");
    options.Fields.Add("name");

    options.Events.OnRemoteFailure = async context =>
    {
        var errorReason = context.Request.Query["error_reason"];
        var errorDescription = context.Request.Query["error_description"];
        var error = context.Request.Query["error"];
        var state = context.Request.Query["state"];

        builder.Logging.AddConsole();
        builder.Logging.SetMinimumLevel(LogLevel.Error);

        Console.WriteLine($"Facebook Authentication failed. Error Reason: {errorReason}, Description: {errorDescription}, Error: {error}, State: {state}");

        if (errorReason == "user_denied")
        {
            context.Response.Redirect("/account/login?error=user_denied");
        }
        else
        {
            context.Response.Redirect("/account/login?error=auth_failure");
        }
    };
});




// Add Razor Pages and Controllers
builder.Services.AddRazorPages().AddRazorRuntimeCompilation();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(dbConnectionString));
builder.Services.AddControllers();

// Add Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Define CORS policy for "AllowSpecificOrigin"
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin", policy =>
    {
        policy.WithOrigins("https://localhost:5000") // Replace with the frontend URL
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

var app = builder.Build();

// HSTS and development configuration
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseSession();  // Add session middleware here

// Enable CORS
app.UseCors("AllowSpecificOrigin");

app.UseRouting();

// Authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();


// Route for Google login
app.MapGet("/login/google", async context =>
{
    var properties = new AuthenticationProperties
    {
        RedirectUri = "/",
    };

    properties.Items["prompt"] = "select_account";  // Force account selection

    await context.ChallengeAsync("Google", properties);
});

// Route for Facebook login
app.MapGet("/login/facebook", async context =>
{
    var properties = new AuthenticationProperties
    {
        RedirectUri = "/",
    };

    properties.Items["prompt"] = "select_account";  // Force account selection

    await context.ChallengeAsync("Facebook", properties);
});


app.MapGet("/logout", async context =>
{
    // Sign out from the local application
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    // Delete cookies and session data
    context.Response.Cookies.Delete(".AspNetCore.Cookies"); // Cookie name used by ASP.NET Core
    context.Session.Clear();

    // Logout from external providers if access token exists
    var accessToken = context.User?.FindFirst("access_token")?.Value;

    if (string.IsNullOrEmpty(accessToken))
    {
        context.Response.Redirect("/logout-success");
    }
    else
    {
        var googleLogoutUrl = "https://accounts.google.com/o/oauth2/revoke?token=" + accessToken;
        context.Response.Redirect(googleLogoutUrl);
    }
});

app.MapGet("/logout-success", () =>
{
    return Results.Content(
        "<html><body>" +
        "<p>You have successfully logged out.</p>" +
        "<a href='/' style='text-decoration: none;'>" +
        "<button style='padding: 10px 20px; font-size: 16px;'>Log back in</button>" +
        "</a>" +
        "<script>" +
        "setTimeout(function() { window.location.href = '/account/login'; }, 2000);" +
        "</script>" +
        "</body></html>",
        "text/html"
    );
});

app.MapGet("/", () => Results.Redirect("/account/login"));

app.MapRazorPages();

app.Run();
