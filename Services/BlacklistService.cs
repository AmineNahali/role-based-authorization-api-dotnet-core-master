namespace WebApi.Services;

using Microsoft.EntityFrameworkCore;
using WebApi.Entities;
using WebApi.Helpers;

public interface IBlacklistService
{
    Task<bool> IsBlacklisted(string email);
    Task AddToBlacklist(string email, string reason = null);
    Task RemoveFromBlacklist(string email);
    Task<List<Blacklist>> GetAllBlacklistedEmails();
}

public class BlacklistService : IBlacklistService
{
    private readonly DataContext _context;

    public BlacklistService(DataContext context)
    {
        _context = context;
    }

    // Method to check if an email is blacklisted
    public async Task<bool> IsBlacklisted(string email)
    {
        return await _context.Blacklisted.AnyAsync(b => b.Email == email);
    }

    // Method to add an email to the blacklist
    public async Task AddToBlacklist(string email, string reason = null)
    {
        if (await IsBlacklisted(email))
        {
            throw new InvalidOperationException("Email is already blacklisted.");
        }

        var blacklistEntry = new Blacklist
        {
            Email = email,
            DateAdded = DateTime.UtcNow,
            Comment = reason
        };

        await _context.Blacklisted.AddAsync(blacklistEntry);
        await _context.SaveChangesAsync();
    }

    // Method to remove an email from the blacklist
    public async Task RemoveFromBlacklist(string email)
    {
        var blacklistEntry = await _context.Blacklisted
            .FirstOrDefaultAsync(b => b.Email == email);

        if (blacklistEntry == null)
        {
            throw new InvalidOperationException("Email is not in the blacklist.");
        }

        _context.Blacklisted.Remove(blacklistEntry);
        await _context.SaveChangesAsync();
    }

    // Optional: Method to retrieve all blacklisted emails (for admin purposes)
    public async Task<List<Blacklist>> GetAllBlacklistedEmails()
    {
        return await _context.Blacklisted.ToListAsync();
    }
}
