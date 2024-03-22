using Microsoft.AspNetCore.Mvc;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Specifies that the class or method that this attribute is applied to requires security API key authorization.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class SecurityKeyAttribute : ServiceFilterAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAttribute"/> class.
    /// </summary>
    public SecurityKeyAttribute() : base(typeof(SecurityKeyAuthorizationFilter))
    {
    }
}
