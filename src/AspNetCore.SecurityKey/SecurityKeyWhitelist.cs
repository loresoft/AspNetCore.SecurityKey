// Ignore Spelling: Whitelist

using System.Net;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides methods to check if an IP address is allowed based on a whitelist of addresses and networks.
/// </summary>
/// <remarks>
/// This class provides IP address filtering capabilities for security purposes, supporting both individual
/// IP addresses and CIDR network ranges for IPv4 and IPv6 addresses.
/// </remarks>
public static class SecurityKeyWhitelist
{
    /// <summary>
    /// Determines whether the specified IP address string is allowed based on the provided allowed addresses and networks.
    /// </summary>
    /// <param name="ipAddress">The IP address string to check. Can be null or empty.</param>
    /// <param name="allowedAddresses">A list of allowed IP addresses in string format. Can be null or empty.</param>
    /// <param name="allowedNetworks">A list of allowed networks in CIDR notation (e.g., "192.168.1.0/24"). Can be null or empty.</param>
    /// <returns>
    /// <c>true</c> if the IP address is allowed; otherwise, <c>false</c>.
    /// Returns <c>true</c> if no restrictions are configured (both lists are null or empty).
    /// Returns <c>false</c> if the IP address is null, empty, or cannot be parsed as a valid IP address.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This is a convenience method that parses the IP address string and delegates to the
    /// <see cref="IsIpAllowed(IPAddress?, IReadOnlyList{string}?, IReadOnlyList{string}?)"/> overload.
    /// </para>
    /// <para>
    /// If no IP restrictions are configured (both <paramref name="allowedAddresses"/> and
    /// <paramref name="allowedNetworks"/> are null or empty), all IP addresses are allowed.
    /// </para>
    /// <para>
    /// If the IP address string cannot be parsed as a valid IPv4 or IPv6 address, the method returns <c>false</c>.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var allowedIPs = new[] { "192.168.1.100", "10.0.0.1" };
    /// var allowedNetworks = new[] { "192.168.0.0/16", "10.0.0.0/8" };
    ///
    /// bool isAllowed1 = SecurityKeyWhitelist.IsIpAllowed("192.168.1.50", allowedIPs, allowedNetworks);
    /// // Returns true because 192.168.1.50 is in the 192.168.0.0/16 network
    ///
    /// bool isAllowed2 = SecurityKeyWhitelist.IsIpAllowed("invalid-ip", allowedIPs, allowedNetworks);
    /// // Returns false because "invalid-ip" cannot be parsed as an IP address
    ///
    /// bool isAllowed3 = SecurityKeyWhitelist.IsIpAllowed("203.0.113.1", null, null);
    /// // Returns true because no restrictions are configured
    /// </code>
    /// </example>
    public static bool IsIpAllowed(string? ipAddress, IReadOnlyList<string>? allowedAddresses, IReadOnlyList<string>? allowedNetworks)
    {
        // If no IP restrictions are configured, allow all
        if (!(allowedAddresses?.Count > 0 || allowedNetworks?.Count > 0))
            return true;

        if (ipAddress == null)
            return false;

       if (IPAddress.TryParse(ipAddress, out var parsedIp))
            return IsIpAllowed(parsedIp, allowedAddresses, allowedNetworks);

       // If parsing fails, treat as not allowed
        return false;
    }

    /// <summary>
    /// Determines whether the specified IP address is allowed based on the provided allowed addresses and networks.
    /// </summary>
    /// <param name="ipAddress">The IP address to check. Can be null.</param>
    /// <param name="allowedAddresses">A list of allowed IP addresses in string format. Can be null or empty.</param>
    /// <param name="allowedNetworks">A list of allowed networks in CIDR notation (e.g., "192.168.1.0/24"). Can be null or empty.</param>
    /// <returns>
    /// <c>true</c> if the IP address is allowed; otherwise, <c>false</c>.
    /// Returns <c>true</c> if no restrictions are configured (both lists are null or empty).
    /// Returns <c>false</c> if the IP address is null, or represents any address (0.0.0.0 or ::).
    /// </returns>
    /// <remarks>
    /// <para>
    /// If no IP restrictions are configured (both <paramref name="allowedAddresses"/> and
    /// <paramref name="allowedNetworks"/> are null or empty), all IP addresses are allowed.
    /// </para>
    /// <para>
    /// The method first checks individual addresses, then network ranges. If the IP address
    /// matches any allowed address or falls within any allowed network, it is considered allowed.
    /// </para>
    /// <para>
    /// IPv4 and IPv6 addresses are supported. Network comparisons ensure address family compatibility.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var allowedIPs = new[] { "192.168.1.100", "10.0.0.1" };
    /// var allowedNetworks = new[] { "192.168.0.0/16", "10.0.0.0/8" };
    /// var clientIP = IPAddress.Parse("192.168.1.50");
    ///
    /// bool isAllowed = SecurityKeyWhitelist.IsIpAllowed(clientIP, allowedIPs, allowedNetworks);
    /// // Returns true because 192.168.1.50 is in the 192.168.0.0/16 network
    /// </code>
    /// </example>
    public static bool IsIpAllowed(IPAddress? ipAddress, IReadOnlyList<string>? allowedAddresses, IReadOnlyList<string>? allowedNetworks)
    {
        // If no IP restrictions are configured, allow all
        if (!(allowedAddresses?.Count > 0 || allowedNetworks?.Count > 0))
            return true;

        if (ipAddress == null)
            return false;

        if (ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.IPv6Any))
            return false;

        // Check AllowedAddresses
        if (allowedAddresses?.Count > 0 && allowedAddresses.Any(addr => IPAddress.TryParse(addr, out var ip) && ip.Equals(ipAddress)))
            return true;

        // Check AllowedNetworks (CIDR)
        if (allowedNetworks?.Count > 0 && allowedNetworks.Any(network => IsIpInNetwork(ipAddress, network)))
            return true;

        return false;
    }

    /// <summary>
    /// Determines whether the specified IP address is within the given network range.
    /// </summary>
    /// <param name="ipAddress">The IP address to check. Can be null.</param>
    /// <param name="network">
    /// The network in CIDR notation (e.g., "192.168.1.0/24" for IPv4 or "2001:db8::/32" for IPv6).
    /// Can be null or empty.
    /// </param>
    /// <returns>
    /// <c>true</c> if the IP address is within the specified network range; otherwise, <c>false</c>.
    /// Returns <c>false</c> if either parameter is null, empty, or if parsing fails.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method supports both IPv4 and IPv6 CIDR notation. The network parameter must be in the
    /// format "baseIP/prefixLength" where prefixLength represents the number of leading bits that
    /// define the network portion.
    /// </para>
    /// <para>
    /// Both the IP address and network base address must be of the same address family (IPv4 or IPv6)
    /// for comparison to succeed.
    /// </para>
    /// <para>
    /// The method performs bitwise comparison of the network portion of the addresses based on the
    /// prefix length specified in the CIDR notation.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var ipAddress = IPAddress.Parse("192.168.1.100");
    /// bool result1 = SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "192.168.1.0/24");
    /// // Returns true - IP is in the 192.168.1.0/24 network
    ///
    /// bool result2 = SecurityKeyWhitelist.IsIpInNetwork(ipAddress, "10.0.0.0/8");
    /// // Returns false - IP is not in the 10.0.0.0/8 network
    ///
    /// var ipv6Address = IPAddress.Parse("2001:db8::1");
    /// bool result3 = SecurityKeyWhitelist.IsIpInNetwork(ipv6Address, "2001:db8::/32");
    /// // Returns true - IPv6 address is in the specified network
    /// </code>
    /// </example>
    /// <exception cref="ArgumentException">
    /// Not thrown directly, but malformed CIDR notation will result in <c>false</c> being returned.
    /// </exception>
    public static bool IsIpInNetwork(IPAddress? ipAddress, string? network)
    {
        if (string.IsNullOrWhiteSpace(network) || ipAddress == null)
            return false;

        try
        {
            // Split the network string into base IP and prefix length (e.g., "192.168.1.0/24")
            var parts = network.Split('/');
            if (parts.Length != 2)
                return false;

            // Try to parse the base IP address
            if (!IPAddress.TryParse(parts[0], out var baseIp))
                return false;

            // Try to parse the prefix length (number of leading bits in the mask)
            if (!int.TryParse(parts[1], out int prefixLength))
                return false;

            var baseBytes = baseIp.GetAddressBytes();
            var remoteBytes = ipAddress.GetAddressBytes();

            // Ensure both IPs are of the same address family (IPv4/IPv6)
            if (baseBytes.Length != remoteBytes.Length)
                return false;

            // Compare the bytes covered by the prefix
            int bytes = prefixLength / 8;
            int bits = prefixLength % 8;

            for (int i = 0; i < bytes; i++)
            {
                if (baseBytes[i] != remoteBytes[i])
                    return false;
            }

            // If there are remaining bits, compare them using a mask
            if (bits > 0)
            {
                int mask = (byte)~(0xFF >> bits);
                if ((baseBytes[bytes] & mask) != (remoteBytes[bytes] & mask))
                    return false;
            }

            // All relevant bits match, IP is in network
            return true;
        }
        catch
        {
            // If parsing fails, treat as not in network
            return false;
        }
    }
}
