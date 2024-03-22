using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

#if NET7_0_OR_GREATER
/// <summary>
/// A filter that requiring security API key authorization.
/// </summary>
public class SecurityKeyEndpointFilter : IEndpointFilter
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;
    private readonly ILogger<SecurityKeyAuthorizationFilter> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyEndpointFilter"/> class.
    /// </summary>
    /// <param name="securityKeyExtractor">The authentication key extractor.</param>
    /// <param name="securityKeyValidator">The authentication key validator.</param>
    /// <param name="logger">The logger.</param>
    public SecurityKeyEndpointFilter(
        ISecurityKeyExtractor securityKeyExtractor,
        ISecurityKeyValidator securityKeyValidator,
        ILogger<SecurityKeyAuthorizationFilter> logger)
    {
        _securityKeyExtractor = securityKeyExtractor ?? throw new ArgumentNullException(nameof(securityKeyExtractor));
        _securityKeyValidator = securityKeyValidator ?? throw new ArgumentNullException(nameof(securityKeyValidator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context is null)
            throw new ArgumentNullException(nameof(context));

        var securityKey = _securityKeyExtractor.GetKey(context.HttpContext);

        if (_securityKeyValidator.Validate(securityKey))
            return await next(context);

        SecurityKeyLogger.InvalidSecurityKey(_logger, securityKey);

        return Results.Unauthorized();
    }
}
#endif
