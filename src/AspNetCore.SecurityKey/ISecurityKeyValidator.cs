namespace AspNetCore.SecurityKey;

public interface ISecurityKeyValidator
{
    bool Validate(string? value);
}
