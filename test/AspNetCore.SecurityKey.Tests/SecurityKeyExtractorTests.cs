using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey.Tests;

public class SecurityKeyExtractorTests
{

    [Fact]
    public void GetKey_FromHeader_ReturnsHeaderValue()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append(securityKeyOptions.HeaderName, "test-security-key");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var extractedKey = securityKeyExtractor.GetKey(httpContext);

        Assert.NotNull(extractedKey);
        Assert.Equal("test-security-key", extractedKey);
    }

    [Fact]
    public void GetKey_FromQuery_ReturnsQueryValue()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var httpContext = new DefaultHttpContext();

        // set query string
        var queryString = $"?{securityKeyOptions.QueryName}=test-security-key";
        httpContext.Request.QueryString = new QueryString(queryString);

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var extractedKey = securityKeyExtractor.GetKey(httpContext);

        Assert.NotNull(extractedKey);
        Assert.Equal("test-security-key", extractedKey);
    }

    [Fact]
    public void GetKey_HeaderAndQueryPresent_ReturnsHeaderValue()
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

        Assert.NotNull(extractedKey);

        // should use header first
        Assert.Equal("test-security-header", extractedKey);
    }

    [Fact]
    public void GetRemoteAddress_FromConnectionRemoteIp_ReturnsRemoteIpAddress()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");
        httpContext.Request.Headers.Append(securityKeyOptions.HeaderName, "test-security-key");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("192.168.1.1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_WithNullContext_ReturnsNull()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(null);

        Assert.Null(remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_WithNoRemoteIpAddress_ReturnsNull()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.Null(remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForSingleIp_ReturnsXForwardedForValue()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "203.0.113.195");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("203.0.113.195"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForMultipleIps_ReturnsFirstIp()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "203.0.113.195, 198.51.100.178, 192.168.1.1");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("203.0.113.195"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForIPv6_ReturnsIPv6Address()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "2001:db8::1");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("2001:db8::1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForWithSpaces_ReturnsTrimmedFirstIp()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "  203.0.113.195  ,  198.51.100.178  ");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("203.0.113.195"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForInvalidIp_FallsBackToRemoteIpAddress()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "invalid-ip");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("192.168.1.1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForEmptyHeader_FallsBackToRemoteIpAddress()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("192.168.1.1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForWhitespaceHeader_FallsBackToRemoteIpAddress()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "   ");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("192.168.1.1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForFirstIpInvalid_FallsBackToRemoteIpAddress()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "invalid-ip, 203.0.113.195");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("192.168.1.1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForOnlyCommas_FallsBackToRemoteIpAddress()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", ",,");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("192.168.1.1"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForWithoutRemoteIp_ReturnsXForwardedForValue()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "203.0.113.195");
        // No RemoteIpAddress set

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("203.0.113.195"), remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForInvalidWithoutRemoteIp_ReturnsNull()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Append("X-Forwarded-For", "invalid-ip");
        // No RemoteIpAddress set

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.Null(remoteAddress);
    }

    [Fact]
    public void GetRemoteAddress_WithLoopbackAddresses_ReturnsLoopbackAddresses()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var securityKeyExtractor = new SecurityKeyExtractor(options);

        // Test IPv4 loopback
        var httpContext1 = new DefaultHttpContext();
        httpContext1.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;

        var remoteAddress1 = securityKeyExtractor.GetRemoteAddress(httpContext1);

        Assert.NotNull(remoteAddress1);
        Assert.Equal(System.Net.IPAddress.Loopback, remoteAddress1);

        // Test IPv6 loopback
        var httpContext2 = new DefaultHttpContext();
        httpContext2.Connection.RemoteIpAddress = System.Net.IPAddress.IPv6Loopback;

        var remoteAddress2 = securityKeyExtractor.GetRemoteAddress(httpContext2);

        Assert.NotNull(remoteAddress2);
        Assert.Equal(System.Net.IPAddress.IPv6Loopback, remoteAddress2);
    }

    [Fact]
    public void GetRemoteAddress_FromXForwardedForCaseInsensitive_ReturnsXForwardedForValue()
    {
        var securityKeyOptions = new SecurityKeyOptions();
        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var httpContext = new DefaultHttpContext();
        // Test case insensitive header name
        httpContext.Request.Headers.Append("x-forwarded-for", "203.0.113.195");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.1");

        var securityKeyExtractor = new SecurityKeyExtractor(options);

        var remoteAddress = securityKeyExtractor.GetRemoteAddress(httpContext);

        Assert.NotNull(remoteAddress);
        Assert.Equal(System.Net.IPAddress.Parse("203.0.113.195"), remoteAddress);
    }
}
