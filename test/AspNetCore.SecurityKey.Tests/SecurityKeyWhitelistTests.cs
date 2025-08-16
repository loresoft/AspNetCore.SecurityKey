using System.Net;

namespace AspNetCore.SecurityKey.Tests;

public class SecurityKeyWhitelistTests
{
    [Fact]
    public void IsIpAllowed_String_NoRestrictionsConfigured_ReturnsTrue()
    {
        // Arrange
        var ipAddress = "192.168.1.100";

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress, null, null));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress, [], []));
    }

    [Fact]
    public void IsIpAllowed_String_NullIpAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100" };
        var allowedNetworks = new[] { "10.0.0.0/8" };

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed((string?)null, allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_String_EmptyIpAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100" };
        var allowedNetworks = new[] { "10.0.0.0/8" };

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("   ", allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_String_InvalidIpAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100" };
        var allowedNetworks = new[] { "10.0.0.0/8" };

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("invalid-ip", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("999.999.999.999", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("192.168.1", allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_String_IPv4AllowedAddress_ReturnsTrue()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100", "10.0.0.1" };
        var allowedNetworks = Array.Empty<string>();

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("192.168.1.100", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("10.0.0.1", allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_String_IPv4NotAllowedAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100", "10.0.0.1" };
        var allowedNetworks = Array.Empty<string>();

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("192.168.1.101", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("172.16.0.1", allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_String_IPv6AllowedAddress_ReturnsTrue()
    {
        // Arrange
        var allowedAddresses = new[] { "2001:db8::1", "::1" };
        var allowedNetworks = Array.Empty<string>();

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("2001:db8::1", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("::1", allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_String_IPv4Network_ReturnsCorrectResult()
    {
        // Arrange
        var allowedAddresses = Array.Empty<string>();
        var allowedNetworks = new[] { "192.168.1.0/24", "10.0.0.0/8" };

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("192.168.1.50", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("192.168.1.255", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("10.255.255.255", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("192.168.2.1", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("172.16.0.1", allowedAddresses, allowedNetworks));
    }


    [Fact]
    public void IsIpAllowed_IPAddress_NoRestrictionsConfigured_ReturnsTrue()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.100");

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress, null, null));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress, [], []));
    }

    [Fact]
    public void IsIpAllowed_IPAddress_NullIpAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100" };
        var allowedNetworks = new[] { "10.0.0.0/8" };

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed((IPAddress?)null, allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_IPAddress_AnyAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100" };
        var allowedNetworks = new[] { "10.0.0.0/8" };

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed(IPAddress.Any, allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed(IPAddress.IPv6Any, allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_IPAddress_AllowedAddress_ReturnsTrue()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100", "10.0.0.1" };
        var allowedNetworks = Array.Empty<string>();
        var ipAddress1 = IPAddress.Parse("192.168.1.100");
        var ipAddress2 = IPAddress.Parse("10.0.0.1");

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress1, allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress2, allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_IPAddress_NotAllowedAddress_ReturnsFalse()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100", "10.0.0.1" };
        var allowedNetworks = Array.Empty<string>();
        var ipAddress1 = IPAddress.Parse("192.168.1.101");
        var ipAddress2 = IPAddress.Parse("172.16.0.1");

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpAllowed(ipAddress1, allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed(ipAddress2, allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_IPAddress_InvalidAddressInAllowedList_IgnoresInvalidEntries()
    {
        // Arrange
        var allowedAddresses = new[] { "192.168.1.100", "invalid-ip", "10.0.0.1" };
        var allowedNetworks = Array.Empty<string>();
        var ipAddress = IPAddress.Parse("10.0.0.1");

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress, allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_IPAddress_IPv6_ReturnsCorrectResult()
    {
        // Arrange
        var allowedAddresses = new[] { "2001:db8::1", "::1" };
        var allowedNetworks = new[] { "2001:db8::/32" };
        var ipAddress1 = IPAddress.Parse("2001:db8::1");
        var ipAddress2 = IPAddress.Parse("2001:db8::5");
        var ipAddress3 = IPAddress.Parse("2001:db9::1");

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress1, allowedAddresses, allowedNetworks)); // Exact match
        Assert.True(SecurityKeyWhitelist.IsIpAllowed(ipAddress2, allowedAddresses, allowedNetworks)); // Network match
        Assert.False(SecurityKeyWhitelist.IsIpAllowed(ipAddress3, allowedAddresses, allowedNetworks)); // No match
    }


    [Fact]
    public void IsIpInNetwork_NullOrEmptyNetwork_ReturnsFalse()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.100");

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, null));
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, ""));
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "   "));
    }

    [Fact]
    public void IsIpInNetwork_NullIpAddress_ReturnsFalse()
    {
        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(null, "192.168.1.0/24"));
    }

    [Fact]
    public void IsIpInNetwork_InvalidNetworkFormat_ReturnsFalse()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.100");

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0")); // Missing prefix
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/24/extra")); // Too many parts
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "invalid-ip/24"));
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/invalid"));
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/999")); // Clearly invalid prefix length
    }

    [Fact]
    public void IsIpInNetwork_IPv4_DifferentPrefixLengths_ReturnsCorrectResult()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.100");

        // Act & Assert
        Assert.True(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/24"));   // /24 network
        Assert.True(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.0.0/16"));   // /16 network
        Assert.True(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.0.0.0/8"));      // /8 network
        Assert.True(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.100/32")); // Exact match

        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.2.0/24"));  // Different /24
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.169.0.0/16"));  // Different /16
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "193.0.0.0/8"));     // Different /8
    }

    [Fact]
    public void IsIpInNetwork_IPv4_EdgeCases_ReturnsCorrectResult()
    {
        // Test edge cases for IPv4
        var tests = new[]
        {
            (IPAddress.Parse("192.168.1.0"), "192.168.1.0/24", true),    // Network address
            (IPAddress.Parse("192.168.1.255"), "192.168.1.0/24", true),  // Broadcast address
            (IPAddress.Parse("192.168.1.1"), "192.168.1.0/30", true),    // Small subnet
            (IPAddress.Parse("192.168.1.4"), "192.168.1.0/30", false),   // Outside small subnet
            (IPAddress.Parse("0.0.0.0"), "0.0.0.0/0", true),             // Any address in 0.0.0.0/0
            (IPAddress.Parse("255.255.255.255"), "0.0.0.0/0", true),     // Any address in 0.0.0.0/0
        };

        foreach (var (ip, network, expected) in tests)
        {
            Assert.Equal(expected, SecurityKeyWhitelist.IsIpInNetwork(ip, network));
        }
    }

    [Fact]
    public void IsIpInNetwork_IPv6_ReturnsCorrectResult()
    {
        // Arrange & Act & Assert
        var tests = new[]
        {
            (IPAddress.Parse("2001:db8::1"), "2001:db8::/32", true),
            (IPAddress.Parse("2001:db8:1::1"), "2001:db8::/32", true),
            (IPAddress.Parse("2001:db9::1"), "2001:db8::/32", false),
            (IPAddress.Parse("2001:db8::1"), "2001:db8::/128", false), // Exact match required
            (IPAddress.Parse("2001:db8::0"), "2001:db8::/128", true),  // Exact match
            (IPAddress.Parse("::1"), "::/0", true),                    // Any IPv6 in ::/0
        };

        foreach (var (ip, network, expected) in tests)
        {
            Assert.Equal(expected, SecurityKeyWhitelist.IsIpInNetwork(ip, network));
        }
    }

    [Fact]
    public void IsIpInNetwork_MismatchedAddressFamilies_ReturnsFalse()
    {
        // Arrange
        var ipv4Address = IPAddress.Parse("192.168.1.100");
        var ipv6Address = IPAddress.Parse("2001:db8::1");

        // Act & Assert
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipv4Address, "2001:db8::/32")); // IPv4 vs IPv6 network
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipv6Address, "192.168.1.0/24")); // IPv6 vs IPv4 network
    }

    [Fact]
    public void IsIpInNetwork_BoundaryConditions_ReturnsCorrectResult()
    {
        // Test boundary conditions for bit masking
        var tests = new[]
        {
            // Test /25 network (25 bits = 3 full bytes + 1 bit)
            (IPAddress.Parse("192.168.1.0"), "192.168.1.0/25", true),
            (IPAddress.Parse("192.168.1.127"), "192.168.1.0/25", true),
            (IPAddress.Parse("192.168.1.128"), "192.168.1.0/25", false),
            (IPAddress.Parse("192.168.1.255"), "192.168.1.0/25", false),

            // Test /23 network (23 bits = 2 full bytes + 7 bits)
            (IPAddress.Parse("192.168.0.255"), "192.168.0.0/23", true),
            (IPAddress.Parse("192.168.1.255"), "192.168.0.0/23", true),
            (IPAddress.Parse("192.168.2.0"), "192.168.0.0/23", false),
        };

        foreach (var (ip, network, expected) in tests)
        {
            Assert.Equal(expected, SecurityKeyWhitelist.IsIpInNetwork(ip, network));
        }
    }

    [Fact]
    public void IsIpInNetwork_ExceptionHandling_ReturnsFalse()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.100");

        // Act & Assert - These should not throw exceptions but return false
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/999")); // Invalid prefix length
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/"));     // Empty prefix
        Assert.False(SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "/24"));              // Empty base IP
    }


    [Fact]
    public void IsIpAllowed_CombinedAddressesAndNetworks_ReturnsCorrectResult()
    {
        // Arrange
        var allowedAddresses = new[] { "10.0.0.1", "203.0.113.5" };
        var allowedNetworks = new[] { "192.168.0.0/16", "172.16.0.0/12" };

        // Act & Assert
        // Direct address matches
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("10.0.0.1", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("203.0.113.5", allowedAddresses, allowedNetworks));

        // Network matches
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("192.168.1.100", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("172.16.255.255", allowedAddresses, allowedNetworks));

        // No matches
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("8.8.8.8", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("172.15.255.255", allowedAddresses, allowedNetworks));
    }

    [Fact]
    public void IsIpAllowed_RealWorldScenarios_ReturnsCorrectResult()
    {
        // Arrange - Common real-world scenarios
        var allowedAddresses = new[] { "127.0.0.1", "::1" }; // localhost
        var allowedNetworks = new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" }; // Private networks

        // Act & Assert
        // Localhost addresses
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("127.0.0.1", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("::1", allowedAddresses, allowedNetworks));

        // Private network addresses
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("10.1.2.3", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("172.16.0.1", allowedAddresses, allowedNetworks));
        Assert.True(SecurityKeyWhitelist.IsIpAllowed("192.168.1.1", allowedAddresses, allowedNetworks));

        // Public addresses (should be blocked)
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("8.8.8.8", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("1.1.1.1", allowedAddresses, allowedNetworks));
        Assert.False(SecurityKeyWhitelist.IsIpAllowed("2001:4860:4860::8888", allowedAddresses, allowedNetworks));
    }
}
