using Microsoft.AspNetCore.Mvc;

namespace AspNetCore.Extensions.SecurityKey;

public class SecurityKeyAttribute : ServiceFilterAttribute
{
    public SecurityKeyAttribute()
        : base(typeof(SecurityKeyAuthorizationFilter))
    {
    }
}
