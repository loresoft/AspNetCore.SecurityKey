using AspNetCore.Extensions.SecurityKey;

using Microsoft.AspNetCore.Mvc;

using Sample.Shared;

namespace Sample.Controllers.Controllers;

[ApiController]
[Route("[controller]")]
public class AddressController : ControllerBase
{
    [SecurityKey]
    [HttpGet(Name = "GetAddresses")]
    public IEnumerable<Address> Get()
    {
        return AddressFaker.Instance.Generate(5);
    }

}
