using System.Security.Claims;
using System.Text.Encodings.Web;

using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

public class SecurityKeyAuthenticationHandler : AuthenticationHandler<SecurityKeyAuthenticationSchemeOptions>
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;

#pragma warning disable CS0618 // allow ISystemClock for compatibility
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

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var securityKey = _securityKeyExtractor.GetKey(Context);

        if (!_securityKeyValidator.Validate(securityKey))
        {
            SecurityKeyLogger.InvalidSecurityKey(Logger, securityKey);
            return Task.FromResult(AuthenticateResult.Fail("Invalid Security Key"));
        }

        // create a user claim for the security key
        var claims = new[] { new Claim(ClaimTypes.Name, "Security Key") };
        var identity = new ClaimsIdentity(claims, SecurityKeyAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
