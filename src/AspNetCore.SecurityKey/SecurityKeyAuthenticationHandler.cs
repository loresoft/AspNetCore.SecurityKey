using System.Security.Claims;
using System.Text.Encodings.Web;

using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Implementation for the cookie-based authentication handler.
/// </summary>
public class SecurityKeyAuthenticationHandler : AuthenticationHandler<SecurityKeyAuthenticationSchemeOptions>
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;

#pragma warning disable CS0618 // allow ISystemClock for compatibility
    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">Accessor to <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <param name="logger">The <see cref="ILoggerFactory"/>.</param>
    /// <param name="encoder">The <see cref="UrlEncoder"/>.</param>
    /// <param name="clock">The <see cref="ISystemClock"/>.</param>
    /// <param name="securityKeyExtractor">The security key extractor.</param>
    /// <param name="securityKeyValidator">The security key validator.</param>
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

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var securityKey = _securityKeyExtractor.GetKey(Context);
        var identity = await _securityKeyValidator.Authenticate(securityKey);

        if (!identity.IsAuthenticated)
            return AuthenticateResult.Fail("Invalid Security Key");

        // create a user claim for the security key
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}
