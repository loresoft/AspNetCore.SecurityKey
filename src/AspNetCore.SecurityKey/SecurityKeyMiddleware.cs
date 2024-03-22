using System.Net;

using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

public class SecurityKeyMiddleware
{
    private readonly RequestDelegate _next;

    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;
    private readonly ILogger<SecurityKeyMiddleware> _logger;

    public SecurityKeyMiddleware(
        RequestDelegate next,
        ISecurityKeyExtractor securityKeyExtractor,
        ISecurityKeyValidator securityKeyValidator,
        ILogger<SecurityKeyMiddleware> logger)
    {
        _next = next;
        _securityKeyExtractor = securityKeyExtractor ?? throw new ArgumentNullException(nameof(securityKeyExtractor));
        _securityKeyValidator = securityKeyValidator ?? throw new ArgumentNullException(nameof(securityKeyValidator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context is null)
            throw new ArgumentNullException(nameof(context));

        var securityKey = _securityKeyExtractor.GetKey(context);

        if (_securityKeyValidator.Validate(securityKey))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        SecurityKeyLogger.InvalidSecurityKey(_logger, securityKey);

        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
    }
}
