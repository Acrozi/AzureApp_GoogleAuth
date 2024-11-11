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
            // Fetch user data from Claims (check for 'name', 'given_name', or 'email')
            var userNameClaim = User.FindFirstValue("name") ?? User.FindFirstValue("given_name");
            var userEmailClaim = User.FindFirstValue(ClaimTypes.Email);

            // Set the properties
            UserName = userNameClaim ?? "Unknown User";
            UserEmail = userEmailClaim ?? "No Email Available";
        }
    }
}
