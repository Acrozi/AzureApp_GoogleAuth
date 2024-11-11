using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using DataTrust.Data;
using DataTrust.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// URLs for the two separate Azure Key Vaults
var dbKeyVaultUrl = "https://database-application.vault.azure.net/"; // Vault for database connection
var googleAuthKeyVaultUrl = "https://googleauthapp.vault.azure.net/"; // Vault for Google OAuth

// Create SecretClient for each Vault
var dbSecretClient = new SecretClient(new Uri(dbKeyVaultUrl), new DefaultAzureCredential());
var googleAuthSecretClient = new SecretClient(new Uri(googleAuthKeyVaultUrl), new DefaultAzureCredential());

// Fetch sensitive values from respective Key Vaults
var dbConnectionString = dbSecretClient.GetSecret("SqlConnectionNew").Value.Value;
var googleClientId = googleAuthSecretClient.GetSecret("ClientId").Value.Value;
var googleClientSecret = googleAuthSecretClient.GetSecret("ClientSecret").Value.Value;

// Logging configuration before services are locked
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug); // For detailed logging

// Add authentication and cookie handling
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "Google";
})
.AddCookie(options =>
{
    // Cookie configuration
    options.Events.OnValidatePrincipal = async context =>
    {
        // Avoid reprocessing the same user during the session
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

        // Attempt to fetch name directly from claims
        var name = context.Principal?.FindFirst("name")?.Value;
        var givenName = context.Principal?.FindFirst(ClaimTypes.GivenName)?.Value;
        var surname = context.Principal?.FindFirst(ClaimTypes.Surname)?.Value;

        // Combine givenName and surname if name is not available
        if (string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(surname))
        {
            name = $"{givenName} {surname}";
        }

        // Set fallback name if name is still null
        name ??= "Unknown User";

        // Validate issuer and subject
        if (subject == null || issuer == null)
        {
            Console.WriteLine("Missing required claims.");
            return;
        }

        var account = db.Accounts.FirstOrDefault(p => p.OpenIDIssuer == issuer && p.OpenIDSubject == subject);
        var email = context.Principal?.FindFirstValue(ClaimTypes.Email);

        if (account == null)
        {
            // First-time login - create user
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
            // Update name or email if they have changed
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
    options.CallbackPath = "/signin-oidc-google"; // Callback path after successful login
    options.SignedOutRedirectUri = "/logout-success"; // Ensure a correct redirect after logout
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
});



// Add authorization and fallback policy
//builder.Services.AddAuthorization(options =>
//{
//    options.FallbackPolicy = new AuthorizationPolicyBuilder()
//       .RequireAuthenticatedUser()
//     .Build();
//});

// Add Razor Pages and Controllers
builder.Services.AddRazorPages().AddRazorRuntimeCompilation();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(dbConnectionString));  // Use connection string from Database Key Vault
builder.Services.AddControllers();

// Add Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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

// Enable CORS
app.UseCors("AllowSpecificOrigin");

app.UseRouting();

// Authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/login", async context =>
{
    await context.ChallengeAsync("Google", new AuthenticationProperties
    {
        RedirectUri = "/"
    });
});

// Logout route
app.MapGet("/logout", async context =>
{
    // Sign out from the authentication scheme (cookie)
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); // Removes the cookie

    // Sign out from Google authentication
    await context.SignOutAsync("Google"); // This will also remove the Google login session

    // Redirect to homepage or login page after logout
    context.Response.Redirect("/login"); // Redirect user to a specified page after logout
});


// Logout success page
app.MapGet("/logout-success", () => Results.Content("You have successfully logged out."));

app.MapGet("/", () => Results.Redirect("/account/login"));

app.MapRazorPages();
app.MapControllers();

app.Run();