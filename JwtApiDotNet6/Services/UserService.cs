using System.Security.Claims;

namespace JwtApiDotNet6.Services;

public class UserService: IUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    public string getMyName()
    {

        var result = String.Empty;
        if (_httpContextAccessor.HttpContext != null)
            result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
        return result;
    }
}