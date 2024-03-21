namespace AspNetCore.Extensions.SecurityKey;

public interface ISecurityKeyValidator
{
    bool Validate(string? value);
}
