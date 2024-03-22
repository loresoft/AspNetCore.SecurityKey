using AspNetCore.Extensions.Authentication;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

public class SecurityKeyValidator : ISecurityKeyValidator
{
    private readonly IConfiguration _configuration;
    private readonly SecurityKeyOptions _securityKeyOptions;
    private readonly ILogger<SecurityKeyValidator> _logger;

    private readonly Lazy<HashSet<string>> _validKeys;

    public SecurityKeyValidator(
        IConfiguration configuration,
        IOptions<SecurityKeyOptions> securityKeyOptions,
        ILogger<SecurityKeyValidator> logger)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _securityKeyOptions = securityKeyOptions?.Value ?? throw new ArgumentNullException(nameof(securityKeyOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // one-time extract keys
        _validKeys = new Lazy<HashSet<string>>(ExractKeys);
    }


    public bool Validate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return _validKeys.Value.Contains(value);
    }

    private HashSet<string> ExractKeys()
    {
        var keyString = _configuration.GetValue<string>(_securityKeyOptions.ConfigurationName) ?? string.Empty;

        SecurityKeyLogger.SecurityKeyUsage(_logger, keyString, _securityKeyOptions.ConfigurationName);

        var keys = keyString.Split([";", ","], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];

        return new HashSet<string>(keys, _securityKeyOptions.KeyComparer);
    }
}
