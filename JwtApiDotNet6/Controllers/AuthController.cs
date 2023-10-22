using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtApiDotNet6.Models;
using JwtApiDotNet6.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtApiDotNet6.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    public static User user = new User();
    private readonly IConfiguration _configuration;
    private readonly IUserService _userService;

    public AuthController(IConfiguration configuration, IUserService userService)
    {
        _configuration = configuration;
        _userService = userService;
    }

    [HttpGet, Authorize]
    public async Task<ActionResult<object>> getMe()
    {
        var userName = _userService.getMyName();
        return Ok(userName);

        // var userName = User.Identity.Name;
        // var userName2 = User.FindFirstValue(ClaimTypes.Name);
        // var role = User.FindFirstValue(ClaimTypes.Role);
        //
        // return Ok(new {userName, userName2, role});
    }

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto request)
    {
        CreatePasswordHash(request.Password,
                           out byte[] passwordHash,
                           out byte[] passwordSalt);

        user.Username = request.Username;
        user.PasswordHash = passwordHash;
        user.PasswordSalt = passwordSalt;

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> login(UserDto request)
    {
        if (user.Username != request.Username)
            return BadRequest("User not found");

        if (!VerifyPasswordSalt(request.Password, user.PasswordHash, user.PasswordSalt))
            return BadRequest("Wrong password");

        string token = CreateToken(user);
        return Ok(token);
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name,user.Username),
            new Claim(ClaimTypes.Role,"Admin")
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes
            (_configuration.GetSection("AppSettings:Token").Value));

        var credentials = new SigningCredentials(key,
            SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(1),
            signingCredentials: credentials);

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        
        return jwt;
    }

    private void CreatePasswordHash(string password, 
                                    out byte[] passwordHash, 
                                    out byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

    private bool VerifyPasswordSalt(string password, 
                                    byte[] passwordHash,
                                    byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512(passwordSalt))
        {
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);
        }
        
        
    }

}