using System.Net;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey.Tests;

public class SecurityKeyValidatorTests
{
    [Fact]
    public async Task ValidateSecurityKey_LegacyFormat_SemicolonSeparated()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "this-is-test;another-test"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate("test");
        Assert.False(result);

        result = await validator.Validate("this-is-test");
        Assert.True(result);

        result = await validator.Validate("another-test");
        Assert.True(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_LegacyFormat_CommaSeparated()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "key1,key2,key3"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate("key1");
        Assert.True(result);

        result = await validator.Validate("key2");
        Assert.True(result);

        result = await validator.Validate("key3");
        Assert.True(result);

        result = await validator.Validate("key4");
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_NewFormat_AllowedKeysOnly()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [$"{securityKeyOptions.ConfigurationName}:AllowedKeys:0"] = "first-key",
            [$"{securityKeyOptions.ConfigurationName}:AllowedKeys:1"] = "second-key",
            [$"{securityKeyOptions.ConfigurationName}:AllowedKeys:2"] = "third-key"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate("first-key");
        Assert.True(result);

        result = await validator.Validate("second-key");
        Assert.True(result);

        result = await validator.Validate("third-key");
        Assert.True(result);

        result = await validator.Validate("invalid-key");
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_NewFormat_WithIpRestrictions()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [$"{securityKeyOptions.ConfigurationName}:AllowedKeys:0"] = "valid-key",
            [$"{securityKeyOptions.ConfigurationName}:AllowedAddresses:0"] = "192.168.1.100",
            [$"{securityKeyOptions.ConfigurationName}:AllowedAddresses:1"] = "10.0.0.1",
            [$"{securityKeyOptions.ConfigurationName}:AllowedNetworks:0"] = "192.168.0.0/16",
            [$"{securityKeyOptions.ConfigurationName}:AllowedNetworks:1"] = "10.0.0.0/8"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        // Valid key with allowed IP address
        var result = await validator.Validate("valid-key", IPAddress.Parse("192.168.1.100"));
        Assert.True(result);

        // Valid key with IP in allowed network
        result = await validator.Validate("valid-key", IPAddress.Parse("192.168.1.50"));
        Assert.True(result);

        // Valid key with IP in another allowed network
        result = await validator.Validate("valid-key", IPAddress.Parse("10.0.0.50"));
        Assert.True(result);

        // Valid key but IP not allowed
        result = await validator.Validate("valid-key", IPAddress.Parse("203.0.113.1"));
        Assert.False(result);

        // Invalid key regardless of IP
        result = await validator.Validate("invalid-key", IPAddress.Parse("192.168.1.100"));
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_CaseSensitive()
    {
        var securityKeyOptions = new SecurityKeyOptions()
        {
            KeyComparer = StringComparer.InvariantCulture
        };

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "this-is-test;another-test"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate("this-is-test");
        Assert.True(result);

        result = await validator.Validate("THIS-IS-TEST");
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_EmptyOrNullKey()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "valid-key"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate(null);
        Assert.False(result);

        result = await validator.Validate("");
        Assert.False(result);

        result = await validator.Validate("   ");
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_NoKeysConfigured()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate("test");
        Assert.False(result);

        result = await validator.Validate("this-is-test");
        Assert.False(result);

        result = await validator.Validate("another-test");
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_EmptyConfiguration()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = ""
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var result = await validator.Validate("test");
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateSecurityKey_TimingAttackProtection()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "short;very-long-security-key-for-testing"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        // Test that keys of different lengths are properly handled
        var result = await validator.Validate("short");
        Assert.True(result);

        result = await validator.Validate("very-long-security-key-for-testing");
        Assert.True(result);

        // Test partial matches don't validate
        result = await validator.Validate("very-long-security-key");
        Assert.False(result);

        result = await validator.Validate("shor");
        Assert.False(result);
    }

    [Fact]
    public async Task Authenticate_ValidKey_ReturnsAuthenticatedIdentity()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "valid-key"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var identity = await validator.Authenticate("valid-key");

        Assert.NotNull(identity);
        Assert.True(identity.IsAuthenticated);
        Assert.Equal(securityKeyOptions.AuthenticationScheme, identity.AuthenticationType);
        Assert.Equal(securityKeyOptions.ClaimNameType, identity.NameClaimType);
        Assert.Equal(securityKeyOptions.ClaimRoleType, identity.RoleClaimType);

        var nameClaim = identity.FindFirst(securityKeyOptions.ClaimNameType);
        Assert.NotNull(nameClaim);
        Assert.Equal("SecurityKey", nameClaim.Value);
    }

    [Fact]
    public async Task Authenticate_InvalidKey_ReturnsUnauthenticatedIdentity()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "valid-key"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var identity = await validator.Authenticate("invalid-key");

        Assert.NotNull(identity);
        Assert.False(identity.IsAuthenticated);
        Assert.Null(identity.AuthenticationType);
    }

    [Fact]
    public async Task Authenticate_ValidKeyWithIpRestriction_ReturnsAuthenticatedIdentity()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [$"{securityKeyOptions.ConfigurationName}:AllowedKeys:0"] = "valid-key",
            [$"{securityKeyOptions.ConfigurationName}:AllowedAddresses:0"] = "192.168.1.100"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var identity = await validator.Authenticate("valid-key", IPAddress.Parse("192.168.1.100"));

        Assert.NotNull(identity);
        Assert.True(identity.IsAuthenticated);
        Assert.Equal(securityKeyOptions.AuthenticationScheme, identity.AuthenticationType);
    }

    [Fact]
    public async Task Authenticate_ValidKeyWithInvalidIp_ReturnsUnauthenticatedIdentity()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [$"{securityKeyOptions.ConfigurationName}:AllowedKeys:0"] = "valid-key",
            [$"{securityKeyOptions.ConfigurationName}:AllowedAddresses:0"] = "192.168.1.100"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var identity = await validator.Authenticate("valid-key", IPAddress.Parse("10.0.0.1"));

        Assert.NotNull(identity);
        Assert.False(identity.IsAuthenticated);
        Assert.Null(identity.AuthenticationType);
    }

    [Fact]
    public async Task Authenticate_CustomClaimTypes_UsesCorrectClaimTypes()
    {
        var securityKeyOptions = new SecurityKeyOptions()
        {
            ClaimNameType = "custom-name",
            ClaimRoleType = "custom-role",
            AuthenticationScheme = "CustomScheme"
        };

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "valid-key"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        var identity = await validator.Authenticate("valid-key");

        Assert.NotNull(identity);
        Assert.True(identity.IsAuthenticated);
        Assert.Equal("CustomScheme", identity.AuthenticationType);
        Assert.Equal("custom-name", identity.NameClaimType);
        Assert.Equal("custom-role", identity.RoleClaimType);

        var nameClaim = identity.FindFirst("custom-name");
        Assert.NotNull(nameClaim);
        Assert.Equal("SecurityKey", nameClaim.Value);
    }

    [Fact]
    public async Task ValidateSecurityKey_CancellationToken_CompletesSuccessfully()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>
        {
            [securityKeyOptions.ConfigurationName] = "valid-key"
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);
        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();
        var validator = new SecurityKeyValidator(configuration, options, logger);

        using var cts = new CancellationTokenSource();

        var result = await validator.Validate("valid-key", cancellationToken: cts.Token);
        Assert.True(result);

        var identity = await validator.Authenticate("valid-key", cancellationToken: cts.Token);
        Assert.True(identity.IsAuthenticated);
    }
}
