using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AspNetCore.Extensions.SecurityKey.Tests;

public class SecurityKeyExtractorTests
{

    [Fact]
    public void ExtraKeyFromHeader()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append(securityKeyOptions.HeaderName, "test-security-key");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var extractedKey = securityKeyExtractor.GetKey(httpContext);

        extractedKey.Should().NotBeNull();
        extractedKey.Should().Be("test-security-key");
    }

    [Fact]
    public void ExtraKeyFromQuery()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var httpContext = new DefaultHttpContext();

        // set query string
        var queryString = $"?{securityKeyOptions.QueryName}=test-security-key";
        httpContext.Request.QueryString = new QueryString(queryString);

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var extractedKey = securityKeyExtractor.GetKey(httpContext);

        extractedKey.Should().NotBeNull();
        extractedKey.Should().Be("test-security-key");
    }

    [Fact]
    public void ExtraKeyFromHeaderPriority()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append(securityKeyOptions.HeaderName, "test-security-header");

        // set query string
        var queryString = $"?{securityKeyOptions.QueryName}=test-security-query";
        httpContext.Request.QueryString = new QueryString(queryString);

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var extractedKey = securityKeyExtractor.GetKey(httpContext);

        extractedKey.Should().NotBeNull();

        // should use header first
        extractedKey.Should().Be("test-security-header");
    }
}
