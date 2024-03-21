using Microsoft.AspNetCore.Mvc;

using Sample.Shared;

namespace Sample.Controllers.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherController : ControllerBase
{
    [HttpGet(Name = "GetWeather")]
    public IEnumerable<Weather> Get()
    {
        return WeatherFaker.Instance.Generate(5);
    }
}
