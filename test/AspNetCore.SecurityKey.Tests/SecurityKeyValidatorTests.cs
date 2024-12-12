using AspNetCore.SecurityKey;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.Extensions.Authentication.Tests;

public class SecurityKeyValidatorTests
{
    [Fact]
    public async Task ValidateSecurityKey()
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
        result.Should().BeFalse();

        result = await validator.Validate("this-is-test");
        result.Should().BeTrue();

        result = await validator.Validate("another-test");
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateSecurityKeyCaseAsync()
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
        result.Should().BeTrue();

        result = await validator.Validate("THIS-IS-TEST");
        result.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateNoKeyFound()
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
        result.Should().BeFalse();

        result = await validator.Validate("this-is-test");
        result.Should().BeFalse();

        result = await validator.Validate("another-test");
        result.Should().BeFalse();
    }
}
