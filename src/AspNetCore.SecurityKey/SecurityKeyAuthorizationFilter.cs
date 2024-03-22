using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

/// <summary>
/// A filter that requiring security API key authorization.
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.Mvc.Filters.IAuthorizationFilter" />
public class SecurityKeyAuthorizationFilter : IAuthorizationFilter
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;
    private readonly ILogger<SecurityKeyAuthorizationFilter> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAuthorizationFilter"/> class.
    /// </summary>
    /// <param name="securityKeyExtractor">The authentication key extractor.</param>
    /// <param name="securityKeyValidator">The authentication key validator.</param>
    /// <param name="logger">The logger.</param>
    public SecurityKeyAuthorizationFilter(
        ISecurityKeyExtractor securityKeyExtractor,
        ISecurityKeyValidator securityKeyValidator,
        ILogger<SecurityKeyAuthorizationFilter> logger)
    {
        _securityKeyExtractor = securityKeyExtractor ?? throw new ArgumentNullException(nameof(securityKeyExtractor));
        _securityKeyValidator = securityKeyValidator ?? throw new ArgumentNullException(nameof(securityKeyValidator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (context is null)
            throw new ArgumentNullException(nameof(context));

        var securityKey = _securityKeyExtractor.GetKey(context.HttpContext);

        if (_securityKeyValidator.Validate(securityKey))
            return;

        SecurityKeyLogger.InvalidSecurityKey(_logger, securityKey);

        context.Result = new UnauthorizedResult();
    }
}
