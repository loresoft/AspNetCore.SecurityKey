using Microsoft.AspNetCore.Http;

namespace AspNetCore.SecurityKey;

public interface ISecurityKeyExtractor
{
    string? GetKey(HttpContext? context);
}
