using DataTrust.Models;
using System.Linq;

namespace DataTrust.Data
{
    public class SampleData
    {
public static void Create(AppDbContext database)
{
    // Kontrollera om databasobjektet är null
    if (database == null)
    {
        throw new ArgumentNullException(nameof(database));
    }

    string fakeIssuer = "https://example.com";

    var existingAccounts = database.Accounts.Where(a => a.OpenIDIssuer == fakeIssuer).ToList();

    if (!existingAccounts.Any())
    {
        database.Accounts.AddRange(new[]
        {
            new Account
            {
                OpenIDIssuer = fakeIssuer,
                OpenIDSubject = "1111111111",
                Name = "Brad",
                Email = "brad@example.com"  // Tilldela ett värde för Email
            },
            new Account
            {
                OpenIDIssuer = fakeIssuer,
                OpenIDSubject = "2222222222",
                Name = "Angelina",
                Email = "angelina@example.com"  // Tilldela ett värde för Email
            },
            new Account
            {
                OpenIDIssuer = fakeIssuer,
                OpenIDSubject = "3333333333",
                Name = "Will",
                Email = "will@example.com"  // Tilldela ett värde för Email
            }
        });

        database.SaveChanges();
    }
}

    }
}
