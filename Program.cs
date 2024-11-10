using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using DataTrust.Data;
using DataTrust.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// URL för de två separata Azure Key Vaults
var dbKeyVaultUrl = "https://database-application.vault.azure.net/"; // Vault för databasanslutning
var googleAuthKeyVaultUrl = "https://googleauthapp.vault.azure.net/"; // Vault för Google OAuth

// Skapa SecretClient för varje Vault
var dbSecretClient = new SecretClient(new Uri(dbKeyVaultUrl), new DefaultAzureCredential());
var googleAuthSecretClient = new SecretClient(new Uri(googleAuthKeyVaultUrl), new DefaultAzureCredential());

// Hämta känsliga värden från respektive Key Vault
var dbConnectionString = dbSecretClient.GetSecret("SqlConnection").Value.Value;
var googleClientId = googleAuthSecretClient.GetSecret("ClientId").Value.Value;
var googleClientSecret = googleAuthSecretClient.GetSecret("ClientSecret").Value.Value;

// Loggning konfigurerad här innan tjänsterna låses
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug); // För detaljerad loggning

// Lägg till autentisering och cookie-hantering
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "Google";
})
.AddCookie(options =>
{
    options.Events.OnValidatePrincipal = async context =>
    {
        // För att undvika upprepad bearbetning av samma användare under sessionen
        if (context.Properties.Items.ContainsKey("Processed"))
        {
            Console.WriteLine("User claims already processed for this session.");
            return;
        }
        context.Properties.Items["Processed"] = "true";

        var serviceProvider = context.HttpContext.RequestServices;
        using var db = new AppDbContext(serviceProvider.GetRequiredService<DbContextOptions<AppDbContext>>());

        string subject = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        string issuer = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Issuer;

        // Försök att hämta namn direkt från claims
        var name = context.Principal?.FindFirst("name")?.Value;
        var givenName = context.Principal?.FindFirst(ClaimTypes.GivenName)?.Value;
        var surname = context.Principal?.FindFirst(ClaimTypes.Surname)?.Value;

        // Kombinera givenName och surname om name inte finns
        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(surname))
        {
            name = $"{givenName} {surname}";
        }

        // Sätt fallback-namn om name fortfarande är tomt
        name ??= "Unknown User";

        // Verifiera att issuer och subject finns
        if (subject == null || issuer == null)
        {
            Console.WriteLine("Missing required claims.");
            return;
        }

        var account = db.Accounts.FirstOrDefault(p => p.OpenIDIssuer == issuer && p.OpenIDSubject == subject);
        var email = context.Principal?.FindFirstValue(ClaimTypes.Email);

        if (account == null)
        {
            // Första inloggning - skapa användaren
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
            // Uppdatera namn eller e-post om de har ändrats
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
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;

    options.SignedOutCallbackPath = "/signout-callback-google";
    options.Events.OnSignedOutCallbackRedirect = context =>
    {
        context.Response.Redirect("/signin-oidc-google");
        return Task.CompletedTask;
    };

    options.Events.OnTokenValidated = context =>
    {
        if (context.Properties.Items.ContainsKey("ClaimsProcessed"))
        {
            Console.WriteLine("Claims already processed.");
            return Task.CompletedTask;
        }

        context.Properties.Items["ClaimsProcessed"] = "true";
        var name = context.Principal?.FindFirst("name")?.Value;
        var givenName = context.Principal?.FindFirst(ClaimTypes.GivenName)?.Value;
        var surname = context.Principal?.FindFirst(ClaimTypes.Surname)?.Value;

        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(surname))
        {
            name = $"{givenName} {surname}";
        }

        Console.WriteLine($"Full Name: {name ?? "Name not found"}");

        return Task.CompletedTask;
    };
});

// Lägg till auktorisering och fallback-policy
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// Lägg till Razor Pages och Controllers
builder.Services.AddRazorPages().AddRazorRuntimeCompilation();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(dbConnectionString));  // Använder Connection String från Databas Key Vault
builder.Services.AddControllers();

// Lägg till Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Lägg till HttpContextAccessor för att komma åt HTTP-sammanhang i controllers
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AccessControl>();

var app = builder.Build();

// HSTS och utvecklingskonfiguration
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
app.UseRouting();

// Middleware för autentisering och auktorisering
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
