using Microsoft.Extensions.Logging;

namespace AspNetCore.Extensions.Authentication;

internal partial class SecurityKeyLogger
{
    [LoggerMessage(1001, LogLevel.Warning, "Invalid Security Key '{SecurityKey}'")]
    internal static partial void InvalidSecurityKey(ILogger logger, string? securityKey);

    [LoggerMessage(1002, LogLevel.Debug, "Using Security Keys '{SecurityKey}' from configuration '{ConfigurationName}'")]
    internal static partial void SecurityKeyUsage(ILogger logger, string? securityKey, string? configurationName);

}
