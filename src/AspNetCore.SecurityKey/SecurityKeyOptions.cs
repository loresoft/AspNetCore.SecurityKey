namespace AspNetCore.SecurityKey;

public class SecurityKeyOptions
{
    public string HeaderName { get; set; } = "x-api-key";

    public string QueryName { get; set; } = "x-api-key";

    public string CookieName { get; set; } = "x-api-key";

    public string ConfigurationName { get; set; } = "SecurityKey";

    public IEqualityComparer<string> KeyComparer { get; set; } = StringComparer.OrdinalIgnoreCase;
}
