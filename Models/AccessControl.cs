using DataTrust.Data;
using DataTrust.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace DataTrust.Data
{
    public class AccessControl
    {
        public int LoggedInAccountID { get; set; }
        public string LoggedInAccountName { get; set; }

        public AccessControl(AppDbContext db, IHttpContextAccessor httpContextAccessor)
        {
            var user = httpContextAccessor.HttpContext?.User;

            // Kontrollera att användaren är autentiserad
            if (user == null || !user.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException("User is not authenticated.");
            }

            // Hämta subject och issuer från claims
            string subject = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            string issuer = user.FindFirst(ClaimTypes.NameIdentifier)?.Issuer;

            if (subject == null || issuer == null)
            {
                throw new InvalidOperationException("Missing required claims for user identification.");
            }

            // Hämta kontot från databasen
            var account = db.Accounts
                .FirstOrDefault(p => p.OpenIDIssuer == issuer && p.OpenIDSubject == subject);

            if (account == null)
            {
                throw new InvalidOperationException("No account found for the current user.");
            }

            LoggedInAccountID = account.Id;

            // Försök hämta användarnamnet från 'Name' claim
            LoggedInAccountName = user.FindFirst(ClaimTypes.Name)?.Value;

            // Om 'Name' claim saknas, logga claims och försök använda 'Email' istället
            if (string.IsNullOrEmpty(LoggedInAccountName))
            {
                Console.WriteLine("Claim 'Name' not found. Available claims:");
                foreach (var claim in user.Claims)
                {
                    Console.WriteLine($"Type: {claim.Type}, Value: {claim.Value}");
                }

                // Använd 'Email' claim som fallback eller 'Unknown' om båda saknas
                LoggedInAccountName = user.FindFirst(ClaimTypes.Email)?.Value ?? "Unknown";
            }
        }
    }
}
