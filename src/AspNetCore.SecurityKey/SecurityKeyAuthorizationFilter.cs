using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

public class SecurityKeyAuthorizationFilter : IAuthorizationFilter
{
    private readonly ISecurityKeyExtractor _authenticationKeyExtractor;
    private readonly ISecurityKeyValidator _authenticationKeyValidator;
    private readonly ILogger<SecurityKeyAuthorizationFilter> _logger;

    public SecurityKeyAuthorizationFilter(
        ISecurityKeyExtractor authenticationKeyExtractor,
        ISecurityKeyValidator authenticationKeyValidator,
        ILogger<SecurityKeyAuthorizationFilter> logger)
    {
        _authenticationKeyExtractor = authenticationKeyExtractor ?? throw new ArgumentNullException(nameof(authenticationKeyExtractor));
        _authenticationKeyValidator = authenticationKeyValidator ?? throw new ArgumentNullException(nameof(authenticationKeyValidator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (context is null)
            throw new ArgumentNullException(nameof(context));

        var securityKey = _authenticationKeyExtractor.GetKey(context.HttpContext);

        if (_authenticationKeyValidator.Validate(securityKey))
            return;

        SecurityKeyLogger.InvalidSecurityKey(_logger, securityKey);

        context.Result = new UnauthorizedResult();
    }
}
