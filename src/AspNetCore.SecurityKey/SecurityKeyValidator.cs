using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

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

    private readonly string[] _allowedKeys;
    private readonly string[] _allowedAddresses;
    private readonly string[] _allowedNetworks;
    private readonly ReadOnlyMemory<byte>[] _allowedKeyBytes;

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

        // cache claims
        _claims = [new Claim(_securityKeyOptions.ClaimNameType, "SecurityKey")];

        // Initialize allowed keys, addresses, networks, and valid key bytes
        (_allowedKeys, _allowedAddresses, _allowedNetworks, _allowedKeyBytes) = LoadConfiguration();
    }

    /// <summary>
    /// Asynchronously authenticates the specified security API key and produces a <see cref="ClaimsIdentity"/> if valid.
    /// </summary>
    /// <param name="value">The security API key to authenticate. May be <c>null</c> if not provided in the request.</param>
    /// <param name="ipAddress">The IP address of the client making the request.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
    /// <returns>
    /// A <see cref="ValueTask{ClaimsIdentity}"/> representing the result of the authentication.
    /// The returned <see cref="ClaimsIdentity"/> reflects the authenticated principal if the key is valid; otherwise, an empty identity.
    /// </returns>
    public async ValueTask<ClaimsIdentity> Authenticate(string? value, IPAddress? ipAddress = null, CancellationToken cancellationToken = default)
    {
        var isValid = await Validate(value, ipAddress, cancellationToken);

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
    /// <param name="ipAddress">The IP address of the client making the request.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to observe while waiting for the task to complete.</param>
    /// <returns>
    /// A <see cref="ValueTask{Boolean}"/> that resolves to <c>true</c> if the security API key is valid; otherwise, <c>false</c>.
    /// </returns>
    public ValueTask<bool> Validate(string? value, IPAddress? ipAddress = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(value))
            return ValueTask.FromResult(false);

        if (!ValidateKey(value))
            return ValueTask.FromResult(false);

        if (!ValidateIpAddress(ipAddress))
            return ValueTask.FromResult(false);

        return ValueTask.FromResult(true);
    }


    private bool ValidateIpAddress(IPAddress? ipAddress)
    {
        if (_allowedAddresses.Length == 0 && _allowedNetworks.Length == 0)
            return true; // No restrictions on IP addresses

        return SecurityKeyWhitelist.IsIpAllowed(
            ipAddress: ipAddress,
            allowedAddresses: _allowedAddresses,
            allowedNetworks: _allowedNetworks);
    }

    private bool ValidateKey(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        var valueBytes = Encoding.UTF8.GetBytes(value);
        foreach (var validKey in _allowedKeyBytes)
        {
            // If the lengths do not match, skip this key
            if (valueBytes.Length != validKey.Length)
                continue;

            // Use CryptographicOperations.FixedTimeEquals to prevent timing attacks
            if (CryptographicOperations.FixedTimeEquals(valueBytes, validKey.Span))
                return true;
        }

        return false;
    }

    private (string[] allowedKeys, string[] allowedAddresses, string[] allowedNetworks, ReadOnlyMemory<byte>[] allowedKeyBytes) LoadConfiguration()
    {
        string[] allowedKeys;
        ReadOnlyMemory<byte>[] allowedKeyBytes;
        string[] allowedAddresses;
        string[] allowedNetworks;

        // Check if the new format exists by looking for AllowedKeys section
        string configurationName = _securityKeyOptions.ConfigurationName;
        var allowedKeysSection = _configuration.GetSection($"{configurationName}:AllowedKeys");

        if (allowedKeysSection?.Exists() == true)
        {
            allowedKeys = allowedKeysSection.Get<string[]>() ?? [];
            allowedKeyBytes = ExtractKeyBytes(allowedKeys);

            allowedAddresses = _configuration.GetSection($"{configurationName}:AllowedAddresses").Get<string[]>() ?? [];
            allowedNetworks = _configuration.GetSection($"{configurationName}:AllowedNetworks").Get<string[]>() ?? [];
        }
        else
        {
            // legacy format: single comma-separated string
            var keys = _configuration.GetValue<string>(configurationName);
            allowedKeys = keys?.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];
            allowedKeyBytes = ExtractKeyBytes(allowedKeys);

            // No addresses or networks configured in legacy format
            allowedAddresses = [];
            allowedNetworks = [];
        }

        if (allowedKeys.Length == 0)
            _logger.LogWarning("No valid security API keys configured. Please set the '{ConfigurationName}' configuration key.", configurationName);
        else
            _logger.LogInformation("Loaded {Count} valid security API keys from configuration.", allowedKeys.Length);

        return (allowedKeys, allowedAddresses, allowedNetworks, allowedKeyBytes);
    }

    private static ReadOnlyMemory<byte>[] ExtractKeyBytes(string[] keys)
    {
        var keyBytes = new ReadOnlyMemory<byte>[keys.Length];

        for (int i = 0; i < keys.Length; i++)
            keyBytes[i] = Encoding.UTF8.GetBytes(keys[i]);

        return keyBytes;
    }
}
