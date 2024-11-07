using DataTrust.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System;
using System.Threading.Tasks;

namespace DataTrust.Controllers
{
    [Route("/api")]
    [ApiController]
    public class APIController : ControllerBase
    {
        private readonly AppDbContext database;

        public APIController(AppDbContext database)
        {
            this.database = database;
        }

        // Logout API
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                // Logga ut från den lokala cookie-autentisering
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // Logga ut från Google OAuth
                await HttpContext.SignOutAsync("Google");

                // Ta bort alla cookies
                foreach (var cookieKey in Request.Cookies.Keys)
                {
                    Response.Cookies.Delete(cookieKey, new CookieOptions
                    {
                        Path = "/",
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    });
                }

                // Omdirigera till login-sidan efter utloggning
                return Redirect("/login"); // Omdirigera användaren till login-sidan
            }
            catch (Exception ex)
            {
                // Hantera eventuella fel som kan uppstå vid utloggningen
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    message = "An error occurred while logging out.",
                    error = ex.Message
                });
            }
        }
    }
}
