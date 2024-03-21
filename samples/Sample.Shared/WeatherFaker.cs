namespace Sample.Shared;

public class WeatherFaker : Faker<Weather>
{
    public WeatherFaker()
    {
        RuleFor(o => o.Date, f => DateOnly.FromDateTime(DateTime.Now.AddDays(f.IndexFaker)));
        RuleFor(o => o.TemperatureC, f => f.Random.Number(-20, 55));
        RuleFor(o => o.Summary, f => f.Random.ArrayElement(["Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"]));
    }

    private static readonly Lazy<WeatherFaker> _instance = new();

    public static WeatherFaker Instance => _instance.Value;

}
