using Microsoft.AspNetCore.Http;

namespace AspNetCore.Extensions.SecurityKey;

public interface ISecurityKeyExtractor
{
    string? GetKey(HttpContext? context);
}
