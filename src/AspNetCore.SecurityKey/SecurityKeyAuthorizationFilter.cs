using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

/// <summary>
/// An asynchronous authorization filter that enforces security API key authorization for controllers or actions.
/// This filter extracts the API key from the current HTTP context and validates it using the configured validator.
/// If the key is missing or invalid, the request is rejected with an <see cref="UnauthorizedResult"/>.
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter" />
public class SecurityKeyAuthorizationFilter : IAsyncAuthorizationFilter
{
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;
    private readonly ILogger<SecurityKeyAuthorizationFilter> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAuthorizationFilter"/> class.
    /// </summary>
    /// <param name="securityKeyExtractor">The service used to extract the security API key from the HTTP context.</param>
    /// <param name="securityKeyValidator">The service used to validate the extracted security API key.</param>
    /// <param name="logger">The logger for diagnostic and error messages.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="securityKeyExtractor"/>, <paramref name="securityKeyValidator"/>, or <paramref name="logger"/> is <c>null</c>.
    /// </exception>
    public SecurityKeyAuthorizationFilter(
        ISecurityKeyExtractor securityKeyExtractor,
        ISecurityKeyValidator securityKeyValidator,
        ILogger<SecurityKeyAuthorizationFilter> logger)
    {
        _securityKeyExtractor = securityKeyExtractor ?? throw new ArgumentNullException(nameof(securityKeyExtractor));
        _securityKeyValidator = securityKeyValidator ?? throw new ArgumentNullException(nameof(securityKeyValidator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Asynchronously authorizes the current request by validating the security API key.
    /// If the key is not valid, sets the result to <see cref="UnauthorizedResult"/> to reject the request.
    /// </summary>
    /// <param name="context">The <see cref="AuthorizationFilterContext"/> for the current request.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="context"/> is <c>null</c>.
    /// </exception>
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var securityKey = _securityKeyExtractor.GetKey(context.HttpContext);

        if (await _securityKeyValidator.Validate(securityKey))
            return;

        context.Result = new UnauthorizedResult();
    }
}
