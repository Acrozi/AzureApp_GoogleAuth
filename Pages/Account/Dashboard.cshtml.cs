using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace GoogleAuth.Pages.Account
{
    [Authorize] // Ensure the user is authenticated
    public class DashboardModel : PageModel
    {
        public string UserName { get; set; }
        public string UserEmail { get; set; }

        public void OnGet()
        {
            // Försök att hämta användarnamn och e-post från Claims (Facebook och Google kan ha olika namn på claims)
            var userNameClaim = User.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name") // Facebook eller OpenID
                ?? User.FindFirstValue("name") // Google (default claim)
                ?? User.FindFirstValue("given_name"); // Alternativt (t.ex. Google)

            var userEmailClaim = User.FindFirstValue(ClaimTypes.Email); // E-post (Google och Facebook använder samma)

            // Sätt värden för användarnamn och e-post
            UserName = userNameClaim ?? "Unknown User";
            UserEmail = userEmailClaim ?? "No Email Available";
        }
    }
}
