using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides an authentication handler for validating requests using a security API key.
/// This handler extracts the API key from the HTTP context and authenticates it using the configured validator.
/// </summary>
public class SecurityKeyAuthenticationHandler : AuthenticationHandler<SecurityKeyAuthenticationSchemeOptions>
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;

#pragma warning disable CS0618 // allow ISystemClock for compatibility
    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor for <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <param name="logger">The factory for creating <see cref="ILogger"/> instances.</param>
    /// <param name="encoder">The <see cref="UrlEncoder"/> for encoding URLs.</param>
    /// <param name="clock">The <see cref="ISystemClock"/> for time-based operations.</param>
    /// <param name="securityKeyExtractor">The service used to extract the security API key from the HTTP context.</param>
    /// <param name="securityKeyValidator">The service used to validate and authenticate the security API key.</param>
    public SecurityKeyAuthenticationHandler(
        IOptionsMonitor<SecurityKeyAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ISecurityKeyExtractor securityKeyExtractor,
        ISecurityKeyValidator securityKeyValidator)
        : base(options, logger, encoder, clock)
    {
        _securityKeyExtractor = securityKeyExtractor;
        _securityKeyValidator = securityKeyValidator;
    }
#pragma warning restore CS0618

    /// <summary>
    /// Handles authentication for the current request by extracting and validating the security API key.
    /// If the key is valid, creates an <see cref="AuthenticationTicket"/> with the authenticated principal.
    /// </summary>
    /// <returns>
    /// An <see cref="AuthenticateResult"/> indicating success or failure of the authentication process.
    /// </returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var securityKey = _securityKeyExtractor.GetKey(Context);

        // If no security key is provided, return no result
        if (string.IsNullOrEmpty(securityKey))
            return AuthenticateResult.NoResult();

        var ipAddress = _securityKeyExtractor.GetRemoteAddress(Context);

        var identity = await _securityKeyValidator.Authenticate(securityKey, ipAddress);
        if (!identity.IsAuthenticated)
            return AuthenticateResult.Fail("Invalid Security Key");

        // create a user claim for the security key
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}
