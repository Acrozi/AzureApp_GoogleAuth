namespace DataTrust.Models
{
    public class Account
    {
        public int Id { get; set; }  // Ensure this is the property you're trying to use
        public string Name { get; set; }
        public string Email { get; set; }
        public string OpenIDSubject { get; set; }
        public string OpenIDIssuer { get; set; }
    }
}
