using System.Net;

using AspNetCore.Extensions.Authentication;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Middleware that enforces security API key authorization for incoming HTTP requests.
/// This middleware extracts the API key from the request using the configured <see cref="ISecurityKeyExtractor"/>,
/// validates it with <see cref="ISecurityKeyValidator"/>, and either allows the request to proceed or
/// responds with a 401 Unauthorized status code if the key is missing or invalid.
/// </summary>
internal sealed class SecurityKeyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ISecurityKeyExtractor _securityKeyExtractor;
    private readonly ISecurityKeyValidator _securityKeyValidator;
    private readonly ILogger<SecurityKeyMiddleware> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the request pipeline.</param>
    /// <param name="securityKeyExtractor">The service used to extract the security API key from the HTTP context.</param>
    /// <param name="securityKeyValidator">The service used to validate the extracted security API key.</param>
    /// <param name="logger">The logger for diagnostic and error messages.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="securityKeyExtractor"/>, <paramref name="securityKeyValidator"/>, or <paramref name="logger"/> is <c>null</c>.
    /// </exception>
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

    /// <summary>
    /// Processes the HTTP request by extracting and validating the security API key.
    /// If the key is valid, the request is passed to the next middleware; otherwise, a 401 Unauthorized response is returned.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> for the current request.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="context"/> is <c>null</c>.
    /// </exception>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var securityKey = _securityKeyExtractor.GetKey(context);

        if (await _securityKeyValidator.Validate(securityKey))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
    }
}
