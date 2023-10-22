namespace JwtApiDotNet6.Models;

public class User
{
    public string Username { get; set; } = String.Empty;
    public byte[] PasswordHash { get; set; } = null!;
    public byte[] PasswordSalt { get; set; } = null!;
}