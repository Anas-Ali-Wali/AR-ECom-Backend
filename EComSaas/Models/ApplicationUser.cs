using Microsoft.AspNetCore.Identity;

namespace EComSaas.Models;

public class ApplicationUser : IdentityUser
{
public string FullName { get; set; } = string.Empty;

    public string? Address { get; set; }

    public string? ProfileImage { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

