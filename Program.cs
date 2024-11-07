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
var dbConnectionString = dbSecretClient.GetSecret("SqlConnectionString").Value.Value;
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
        var serviceProvider = context.HttpContext.RequestServices;
        using var db = new AppDbContext(serviceProvider.GetRequiredService<DbContextOptions<AppDbContext>>());

        string subject = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        string issuer = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Issuer;
        
        // Försök att hämta namn direkt från claims
        var name = context.Principal?.FindFirst("name")?.Value;

        // Debugging: logga namn
        Console.WriteLine($"Processing user: {name}");

        // Debugging: logga alla claims
        var claims = context.Principal.Claims;
        foreach (var claim in claims)
        {
            Console.WriteLine($"Claim Type: {claim.Type}, Claim Value: {claim.Value}");
        }

        // Hantera givenname och surname för att skapa ett fullständigt namn om möjligt
        var givenName = context.Principal?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")?.Value;
        var surname = context.Principal?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")?.Value;
        
        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(surname))
        {
            // Kombinera förnamn och efternamn om name inte finns
            name = $"{givenName} {surname}";
        }

        // Om namn fortfarande är null eller tomt, använd ett standardvärde
        if (string.IsNullOrEmpty(name))
        {
            name = "Unknown User"; // Fallback namn
        }

        if (subject == null || issuer == null)
        {
            Console.WriteLine("Missing required claims.");
            return;
        }

        var account = db.Accounts
            .FirstOrDefault(p => p.OpenIDIssuer == issuer && p.OpenIDSubject == subject);

        if (account == null)
        {
            // Första inloggning - skapa användaren
            account = new Account
            {
                OpenIDIssuer = issuer,
                OpenIDSubject = subject,
                Name = name, // Sätt användarnamn
                Email = context.Principal?.FindFirstValue(ClaimTypes.Email) // Spara e-postadressen
            };
            db.Accounts.Add(account);
        }
        else
        {
            // Användare finns - uppdatera vid behov
            account.Name = name; // Uppdatera namn
            account.Email = context.Principal?.FindFirstValue(ClaimTypes.Email); // Uppdatera e-postadressen
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

    // Lägg till EndSessionEndpoint för att hantera logout korrekt
    options.SignedOutCallbackPath = "/signout-callback-google";
    options.Events.OnSignedOutCallbackRedirect = context =>
    {
        context.Response.Redirect("https://google-auth-mysql-dkgacucuh0fbethz.westeurope-01.azurewebsites.net/signin-oidc-google");
        return Task.CompletedTask;
    };

    // Debugging event for claims
    options.Events.OnTokenValidated = context =>
    {
        var claims = context.Principal.Claims;
        foreach (var claim in claims)
        {
            Console.WriteLine($"Claim Type: {claim.Type}, Claim Value: {claim.Value}");
        }

        // Hantera namn från claims
        var givenName = context.Principal?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")?.Value;
        var surname = context.Principal?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")?.Value;
        var name = context.Principal?.FindFirst("name")?.Value;

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
app.UseAuthentication(); // Se till att denna är före UseAuthorization
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

// Skapa exempeldata om det inte finns
//using (var scope = app.Services.CreateScope())
//{
//   var services = scope.ServiceProvider;
//   var context = services.GetRequiredService<AppDbContext>();
//  SampleData.Create(context);
//}

app.Run();
