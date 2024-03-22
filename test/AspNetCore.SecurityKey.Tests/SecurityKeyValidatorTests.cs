using AspNetCore.SecurityKey;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.Extensions.Authentication.Tests;

public class SecurityKeyValidatorTests
{
    [Fact]
    public void ValidateSecurityKey()
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

        validator.Validate("test").Should().BeFalse();
        validator.Validate("this-is-test").Should().BeTrue();
        validator.Validate("another-test").Should().BeTrue();
    }

    [Fact]
    public void ValidateSecurityKeyCase()
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

        validator.Validate("this-is-test").Should().BeTrue();
        validator.Validate("THIS-IS-TEST").Should().BeFalse();
    }

    [Fact]
    public void ValidateNoKeyFound()
    {
        var securityKeyOptions = new SecurityKeyOptions();

        var settings = new Dictionary<string, string?>();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var options = new OptionsWrapper<SecurityKeyOptions>(securityKeyOptions);

        var logger = NullLoggerFactory.Instance.CreateLogger<SecurityKeyValidator>();

        var validator = new SecurityKeyValidator(configuration, options, logger);

        validator.Validate("test").Should().BeFalse();
        validator.Validate("this-is-test").Should().BeFalse();
        validator.Validate("another-test").Should().BeFalse();
    }
}
