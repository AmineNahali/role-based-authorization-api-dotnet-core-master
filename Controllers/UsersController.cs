namespace WebApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models.Users;
using WebApi.Services;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    [AllowAnonymous]
    [HttpPost("[action]")]
    public async Task<IActionResult> Authenticate(AuthenticateRequest model)
    {
        var response = await _userService.Authenticate(model);
        return Ok(response);
    }
    
    [AllowAnonymous]
    [HttpPost("[action]")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        var response = await _userService.Register(model);
        return Ok(response);
    }
    
    [Authorize(Role.Admin)]
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var users = await _userService.GetAll();
        return Ok(users);
    }

    [HttpGet("{id:long}")]
    public async Task<IActionResult> GetById_AsAdmin(long id)
    {
        // only admins can access other user records including other admins
        var currentUser = (User)HttpContext.Items["User"];
        
        if (currentUser == null || currentUser.Role != Role.Admin)
            return Unauthorized(new { message = "Unauthorized" });

        var user = await _userService.GetById(id);
        return Ok(user);
    }
}