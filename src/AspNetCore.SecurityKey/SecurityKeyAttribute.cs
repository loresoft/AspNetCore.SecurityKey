using Microsoft.AspNetCore.Mvc;

namespace AspNetCore.SecurityKey;

public class SecurityKeyAttribute : ServiceFilterAttribute
{
    public SecurityKeyAttribute()
        : base(typeof(SecurityKeyAuthorizationFilter))
    {
    }
}
