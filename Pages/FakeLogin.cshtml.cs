using DataTrust.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using System;

namespace DataTrust.Pages
{
    public class FakeLoginModel : PageModel
    {
        private readonly AppDbContext database;
        private readonly IWebHostEnvironment environment;

        // Constructor to inject dependencies
        public FakeLoginModel(AppDbContext database, IWebHostEnvironment environment)
        {
            this.database = database;
            this.environment = environment;
        }

        // Log in as the user with the specified account ID, without providing a password etc.
        // IMPORTANT: This should only be allowed in development, hence the if statement below.
        public async Task<IActionResult> OnPost(int accountID)
        {
            // Kontrollera att det är utvecklingsläge
            if (!environment.IsDevelopment())
            {
                return Forbid(); // Förhindra åtkomst om det inte är i utvecklingsläge
            }

            // Hämta användarkontot från databasen
            var account = database.Accounts.Find(accountID);

            // Kontrollera om kontot finns och om det har nödvändig data
            if (account == null)
            {
                return NotFound("Account not found.");
            }

            if (string.IsNullOrEmpty(account.OpenIDSubject))
            {
                return BadRequest("OpenIDSubject is missing.");
            }

            if (string.IsNullOrEmpty(account.Name) || account.Name.Contains("Unknown"))
            {
                return BadRequest("Account is invalid or marked as 'Unknown'. Login is not allowed.");
            }

            // Skapa ClaimsIdentity för användaren
            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, account.OpenIDSubject)); // OpenIDSubject som identifierare
            identity.AddClaim(new Claim(ClaimTypes.Name, account.Name)); // Användarens namn
            identity.AddClaim(new Claim(ClaimTypes.Email, account.Email)); // Användarens e-post

            var principal = new ClaimsPrincipal(identity);

            try
            {
                // Försök logga in med den skapade identiteten
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error signing in: {ex.Message}");
            }

            return RedirectToPage("./Index"); // Redirect till start-sidan efter lyckad inloggning
        }
    }
}
