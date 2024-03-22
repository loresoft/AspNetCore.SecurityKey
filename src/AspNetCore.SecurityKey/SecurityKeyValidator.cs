using AspNetCore.Extensions.Authentication;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Default implementation for validating the security API key
/// </summary>
/// <seealso cref="AspNetCore.SecurityKey.ISecurityKeyValidator" />
public class SecurityKeyValidator : ISecurityKeyValidator
{
    private readonly IConfiguration _configuration;
    private readonly SecurityKeyOptions _securityKeyOptions;
    private readonly ILogger<SecurityKeyValidator> _logger;

    private readonly Lazy<HashSet<string>> _validKeys;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyValidator"/> class.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="securityKeyOptions">The security key options.</param>
    /// <param name="logger">The logger.</param>
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

    /// <inheritdoc />
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
