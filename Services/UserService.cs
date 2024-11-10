namespace WebApi.Services;

using BCryptNet = BCrypt.Net.BCrypt;
using Microsoft.Extensions.Options;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Models.Users;
using Microsoft.EntityFrameworkCore;

public interface IUserService
{
    Task<RegisterResponse> Register(RegisterRequest model);
    Task<AuthenticateResponse> Authenticate(AuthenticateRequest model);
    Task<IEnumerable<User>> GetAll();
    Task<User> GetById(long id);
}

public class UserService : IUserService
{
    private DataContext _context;
    private IJwtUtils _jwtUtils;
    private readonly AppSettings _appSettings;

    public UserService(
        DataContext context,
        IJwtUtils jwtUtils,
        IOptions<AppSettings> appSettings)
    {
        _context = context;
        _jwtUtils = jwtUtils;
        _appSettings = appSettings.Value;
    }

    public async Task<RegisterResponse> Register(RegisterRequest model)
    {
        //TODO: Check if user's email already exists

        //TODO: Check if user's email is blacklisted
        var this_instant = DateTime.UtcNow;
        var new_user = new User
        {
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            PasswordHash = BCryptNet.HashPassword(model.Password1),
            Role = Role.User,
            DateCreated = this_instant,
            DateLastModified = this_instant,
            DateLastPasswordModified = this_instant,
            IsActivated = true,
        };
        await _context.Users.AddAsync(new_user);
        await _context.SaveChangesAsync();

        return new RegisterResponse { Email = new_user.Email };
    }

    public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest model)
    {
        var user = await _context.Users.SingleOrDefaultAsync(x => x.Email == model.Email);

        // validate
        if (user == null || !BCryptNet.Verify(model.Password, user.PasswordHash))
            throw new AppException("Username or password is incorrect");

        // authentication successful so generate jwt token
        var jwtToken = _jwtUtils.GenerateJwtToken(user);

        return new AuthenticateResponse(user, jwtToken);
    }



    public async Task<IEnumerable<User>> GetAll()
    {
        return await _context.Users.ToListAsync();
    }

    public async Task<User> GetById(long id) 
    {
        var user = await _context.Users.FindAsync(id);
        if (user == null) throw new KeyNotFoundException("User not found");
        return user;
    }
}