using Microsoft.AspNetCore.Mvc;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Indicates that the decorated controller or action requires security API key authorization.
/// When applied, requests must provide a valid API key to access the resource.
/// This attribute uses <see cref="SecurityKeyAuthorizationFilter"/> to enforce authorization.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class SecurityKeyAttribute : ServiceFilterAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAttribute"/> class,
    /// configuring it to use <see cref="SecurityKeyAuthorizationFilter"/> for API key validation.
    /// </summary>
    public SecurityKeyAttribute() : base(typeof(SecurityKeyAuthorizationFilter))
    {
    }
}
