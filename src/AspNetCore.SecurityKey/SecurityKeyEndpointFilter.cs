using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

#if NET7_0_OR_GREATER
/// <summary>
/// An endpoint filter that enforces security API key authorization for minimal API route handlers.
/// This filter extracts the API key from the current HTTP context and validates it using the configured validator.
/// If the key is missing or invalid, the request is rejected with an unauthorized result.
/// </summary>
public class SecurityKeyEndpointFilter : IEndpointFilter
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;
    private readonly ILogger<SecurityKeyEndpointFilter> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyEndpointFilter"/> class.
    /// </summary>
    /// <param name="securityKeyExtractor">The service used to extract the security API key from the HTTP context.</param>
    /// <param name="securityKeyValidator">The service used to validate the extracted security API key.</param>
    /// <param name="logger">The logger for diagnostic and error messages.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="securityKeyExtractor"/>, <paramref name="securityKeyValidator"/>, or <paramref name="logger"/> is <c>null</c>.
    /// </exception>
    public SecurityKeyEndpointFilter(
        ISecurityKeyExtractor securityKeyExtractor,
        ISecurityKeyValidator securityKeyValidator,
        ILogger<SecurityKeyEndpointFilter> logger)
    {
        _securityKeyExtractor = securityKeyExtractor ?? throw new ArgumentNullException(nameof(securityKeyExtractor));
        _securityKeyValidator = securityKeyValidator ?? throw new ArgumentNullException(nameof(securityKeyValidator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Invokes the endpoint filter to validate the security API key for the current request.
    /// If the key is valid, the request proceeds to the next filter or handler; otherwise, an unauthorized result is returned.
    /// </summary>
    /// <param name="context">The <see cref="EndpointFilterInvocationContext"/> for the current request.</param>
    /// <param name="next">The delegate representing the next filter or endpoint handler in the pipeline.</param>
    /// <returns>
    /// A <see cref="ValueTask{Object}"/> that resolves to the result of the next filter or handler if authorized, or an unauthorized result if not.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="context"/> is <c>null</c>.
    /// </exception>
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);

        var securityKey = _securityKeyExtractor.GetKey(context.HttpContext);

        if (await _securityKeyValidator.Validate(securityKey))
            return await next(context);

        return Results.Unauthorized();
    }
}
#endif
