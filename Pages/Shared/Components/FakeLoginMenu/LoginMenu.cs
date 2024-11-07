using DataTrust.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace DataTrust.Pages.Shared.Components.LoginMenu
{
    public class FakeLoginMenu : ViewComponent
    {
        private readonly AppDbContext database;
        private readonly AccessControl accessControl;

        public FakeLoginMenu(AppDbContext database, AccessControl accessControl)
        {
            this.database = database;
            this.accessControl = accessControl;
        }

        public async Task<IViewComponentResult> InvokeAsync(int maxPriority, bool isDone)
        {
            var accounts = database.Accounts.OrderBy(a => a.Name);
            var selectList = accounts.Select(p => new SelectListItem
            {
                Value = p.Id.ToString(),  // Ändra här från p.ID till p.Id
                Text = p.Name,
                Selected = p.Id == accessControl.LoggedInAccountID  // Ändra här från p.ID till p.Id
            });
            return View(selectList);
        }
    }
}
