using AspNetCore.Extensions.SecurityKey;

using Microsoft.AspNetCore.Mvc;

using Sample.Shared;

namespace Sample.Controllers.Controllers;

[ApiController]
[Route("[controller]")]
[SecurityKey]
public class UserController : ControllerBase
{
    [HttpGet(Name = "GetUsers")]
    public IEnumerable<User> Get()
    {
        return UserFaker.Instance.Generate(5);
    }

}
