using Microsoft.Extensions.Logging;

namespace AspNetCore.Extensions.Authentication;

public partial class SecurityKeyLogger
{
    [LoggerMessage(1001, LogLevel.Error, "Invalid Security Key '{SecurityKey}'")]
    public static partial void InvalidSecurityKey(ILogger logger, string? securityKey);

    [LoggerMessage(1002, LogLevel.Debug, "Using Security Keys '{SecurityKey}' from configuration '{ConfigurationName}'")]
    public static partial void SecurityKeyUsage(ILogger logger, string? securityKey, string? configurationName);

}
