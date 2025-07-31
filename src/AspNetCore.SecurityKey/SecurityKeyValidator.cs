using System.Security.Claims;

using AspNetCore.Extensions.Authentication;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides the default implementation for validating and authenticating security API keys.
/// This validator retrieves valid keys from configuration, compares incoming keys using the configured comparer,
/// and produces authentication identities for valid keys.
/// </summary>
/// <seealso cref="AspNetCore.SecurityKey.ISecurityKeyValidator" />
public class SecurityKeyValidator : ISecurityKeyValidator
{
    private readonly IConfiguration _configuration;
    private readonly SecurityKeyOptions _securityKeyOptions;
    private readonly ILogger<SecurityKeyValidator> _logger;

    private readonly Lazy<HashSet<string>> _validKeys;
    private readonly Claim[] _claims;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyValidator"/> class.
    /// </summary>
    /// <param name="configuration">The configuration source used to retrieve valid security API keys.</param>
    /// <param name="securityKeyOptions">The options specifying key extraction, comparison, and claim settings.</param>
    /// <param name="logger">The logger for diagnostic and error messages.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="configuration"/>, <paramref name="securityKeyOptions"/>, or <paramref name="logger"/> is <c>null</c>.
    /// </exception>
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
        _claims = [new Claim(_securityKeyOptions.ClaimNameType, "SecurityKey")];
    }

    /// <summary>
    /// Asynchronously authenticates the specified security API key and produces a <see cref="ClaimsIdentity"/> if valid.
    /// </summary>
    /// <param name="value">The security API key to authenticate. May be <c>null</c> if not provided in the request.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
    /// <returns>
    /// A <see cref="ValueTask{ClaimsIdentity}"/> representing the result of the authentication.
    /// The returned <see cref="ClaimsIdentity"/> reflects the authenticated principal if the key is valid; otherwise, an empty identity.
    /// </returns>
    public async ValueTask<ClaimsIdentity> Authenticate(string? value, CancellationToken cancellationToken = default)
    {
        var isValid = await Validate(value, cancellationToken);

        if (!isValid)
            return new ClaimsIdentity();

        return new ClaimsIdentity(
            claims: _claims,
            authenticationType: _securityKeyOptions.AuthenticationScheme,
            nameType: _securityKeyOptions.ClaimNameType,
            roleType: _securityKeyOptions.ClaimRoleType);
    }

    /// <summary>
    /// Asynchronously validates the specified security API key.
    /// </summary>
    /// <param name="value">The security API key to validate. May be <c>null</c> or whitespace if not provided in the request.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
    /// <returns>
    /// A <see cref="ValueTask{Boolean}"/> that resolves to <c>true</c> if the security API key is valid; otherwise, <c>false</c>.
    /// </returns>
    public ValueTask<bool> Validate(string? value, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(value))
            return ValueTask.FromResult(false);

        return ValueTask.FromResult(_validKeys.Value.Contains(value));
    }

    /// <summary>
    /// Extracts the set of valid security API keys from configuration.
    /// Keys are split using ';' or ',' and trimmed; empty entries are ignored.
    /// </summary>
    /// <returns>
    /// A <see cref="HashSet{String}"/> containing all valid security API keys.
    /// </returns>
    private HashSet<string> ExractKeys()
    {
        var keyString = _configuration.GetValue<string>(_securityKeyOptions.ConfigurationName) ?? string.Empty;

        SecurityKeyLogger.SecurityKeyUsage(_logger, keyString, _securityKeyOptions.ConfigurationName);

        var keys = keyString.Split([';', ','], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries) ?? [];

        return new HashSet<string>(keys, _securityKeyOptions.KeyComparer);
    }
}
