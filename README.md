# Security API Keys for ASP.NET Core

A flexible and lightweight API key authentication library for ASP.NET Core applications that supports multiple authentication patterns and integrates seamlessly with ASP.NET Core's authentication and authorization infrastructure.

[![Build Project](https://github.com/loresoft/AspNetCore.SecurityKey/actions/workflows/dotnet.yml/badge.svg)](https://github.com/loresoft/AspNetCore.SecurityKey/actions/workflows/dotnet.yml)

[![Coverage Status](https://coveralls.io/repos/github/loresoft/AspNetCore.SecurityKey/badge.svg?branch=main)](https://coveralls.io/github/loresoft/AspNetCore.SecurityKey?branch=main)

[![AspNetCore.SecurityKey](https://img.shields.io/nuget/v/AspNetCore.SecurityKey.svg)](https://www.nuget.org/packages/AspNetCore.SecurityKey/)

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [How to Pass API Keys](#how-to-pass-api-keys)
- [Configuration](#configuration)
- [IP Address Whitelisting](#ip-address-whitelisting)
- [Usage Patterns](#usage-patterns)
- [Advanced Customization](#advanced-customization)
- [OpenAPI/Swagger Integration](#openapiswagger-integration)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Examples Repository](#examples-repository)
- [Contributing](#contributing)
- [License](#license)

## Overview

AspNetCore.SecurityKey provides a complete API key authentication solution for ASP.NET Core applications with support for modern development patterns and best practices.

**Key Features:**

- **Multiple Input Sources** - API keys via headers, query parameters, or cookies
- **Flexible Authentication** - Works with ASP.NET Core's built-in authentication or as standalone middleware
- **IP Address Whitelisting** - Restrict API access by IP addresses and network ranges (IPv4 and IPv6)
- **Extensible Design** - Custom validation and extraction logic support
- **Rich Integration** - Controller attributes, middleware, and minimal API support
- **OpenAPI Support** - Automatic Swagger/OpenAPI documentation generation (.NET 9+)
- **High Performance** - Minimal overhead with optional caching and timing-attack protection
- **Multiple Deployment Patterns** - Attribute-based, middleware, or endpoint filters

## Quick Start

1. **Install the package**:

   ```shell
   dotnet add package AspNetCore.SecurityKey
   ```

2. **Configure your API key** in `appsettings.json`:

   ```json
   {
     "SecurityKey": "your-secret-api-key-here"
   }
   ```

3. **Register services** and secure endpoints:

   ```csharp
   builder.Services.AddSecurityKey();
   app.UseSecurityKey(); // Secures all endpoints
   ```

4. **Call your API** with the key:

   ```bash
   curl -H "X-API-KEY: your-secret-api-key-here" https://yourapi.com/endpoint
   ```

## Installation

The library is available on [nuget.org](https://www.nuget.org/packages/AspNetCore.SecurityKey/) via package name `AspNetCore.SecurityKey`.

### Package Manager Console

```powershell
Install-Package AspNetCore.SecurityKey
```

### .NET CLI

```shell
dotnet add package AspNetCore.SecurityKey
```

### PackageReference

```xml
<PackageReference Include="AspNetCore.SecurityKey" />
```

## How to Pass API Keys

AspNetCore.SecurityKey supports multiple ways to pass API keys in requests, providing flexibility for different client scenarios:

### Request Headers (Recommended)

The most common and secure approach for API-to-API communication:

```http
GET https://api.example.com/users
Accept: application/json
X-API-KEY: 01HSGVBSF99SK6XMJQJYF0X3WQ
```

### Query Parameters

Useful for simple integrations or when headers cannot be easily modified:

```http
GET https://api.example.com/users?X-API-KEY=01HSGVBSF99SK6XMJQJYF0X3WQ
Accept: application/json
```

> ⚠️ **Security Note**: When using query parameters, be aware that API keys may appear in server logs, browser history, and referrer headers. Headers are generally preferred for production use.

### Cookies

Ideal for browser-based applications or when API keys need persistence:

```http
GET https://api.example.com/users
Accept: application/json
Cookie: X-API-KEY=01HSGVBSF99SK6XMJQJYF0X3WQ
```

## Configuration

### Basic Setup

Configure your API keys in `appsettings.json`:

```json
{
  "SecurityKey": "01HSGVBSF99SK6XMJQJYF0X3WQ"
}
```

### Multiple API Keys

Support multiple valid API keys using semicolon separation:

```json
{
  "SecurityKey": "01HSGVBGWXWDWTFGTJSYFXXDXQ;01HSGVBSF99SK6XMJQJYF0X3WQ;01HSGVAH2M5WVQYG4YPT7FNK4K8"
}
```

### Enhanced Configuration Format

For advanced scenarios with IP whitelisting and multiple keys, use the enhanced configuration format:

```json
{
  "SecurityKey": {
    "AllowedKeys": [
      "01HSGVBGWXWDWTFGTJSYFXXDXQ",
      "01HSGVBSF99SK6XMJQJYF0X3WQ",
      "01HSGVAH2M5WVQYG4YPT7FNK4K8"
    ],
    "AllowedAddresses": [
      "192.168.1.100",
      "10.0.0.1",
      "203.0.113.50",
      "::1"
    ],
    "AllowedNetworks": [
      "192.168.0.0/16",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "2001:db8::/32"
    ]
  }
}
```

### Advanced Options

Customize key extraction and validation behavior:

```csharp
builder.Services.AddSecurityKey(options =>
{
    // Custom configuration path
    options.ConfigurationName = "Authentication:ApiKey";
    
    // Customize header name (default: "x-api-key")
    options.HeaderName = "API-KEY";
    
    // Customize query parameter name (default: "x-api-key") 
    options.QueryName = "apikey";
    
    // Customize cookie name (default: "x-api-key")
    options.CookieName = "app-api-key";
    
    // Case-sensitive key comparison (default: case-insensitive)
    options.KeyComparer = StringComparer.Ordinal;
    
    // Custom authentication scheme name
    options.AuthenticationScheme = "CustomApiKey";
    
    // Claims configuration
    options.ClaimNameType = ClaimTypes.Name;
    options.ClaimRoleType = ClaimTypes.Role;
    
    // Optional caching for performance
    options.CacheTime = TimeSpan.FromMinutes(5);
});
```

## IP Address Whitelisting

AspNetCore.SecurityKey provides built-in IP address whitelisting capabilities to restrict API access based on client IP addresses. This feature supports both IPv4 and IPv6 addresses, individual IPs, and network ranges using CIDR notation.

### Configuration

IP whitelisting is configured using the enhanced configuration format in `appsettings.json`:

```json
{
  "SecurityKey": {
    "AllowedKeys": ["your-api-key-here"],
    "AllowedAddresses": [
      "192.168.1.100",      // Specific IPv4 address
      "10.0.0.1",           // Another IPv4 address
      "::1",                // IPv6 localhost
      "2001:db8::1"         // Specific IPv6 address
    ],
    "AllowedNetworks": [
      "192.168.0.0/16",     // Private network range
      "10.0.0.0/8",         // Class A private network
      "172.16.0.0/12",      // Class B private network
      "2001:db8::/32"       // IPv6 network range
    ]
  }
}
```

### How It Works

1. **No Restrictions**: If neither `AllowedAddresses` nor `AllowedNetworks` are configured, all IP addresses are allowed
2. **Address Matching**: Client IP is checked against the `AllowedAddresses` list for exact matches
3. **Network Matching**: Client IP is checked against the `AllowedNetworks` list using CIDR notation
4. **Combined Logic**: A request is allowed if the IP matches either an allowed address OR falls within an allowed network

### Common Use Cases

#### Development Environment
Allow only local development machines:

```json
{
  "SecurityKey": {
    "AllowedKeys": ["dev-key-123"],
    "AllowedAddresses": [
      "127.0.0.1",          // IPv4 localhost
      "::1"                 // IPv6 localhost
    ],
    "AllowedNetworks": [
      "192.168.0.0/16"      // Local network
    ]
  }
}
```

#### Corporate Environment
Allow only internal corporate networks:

```json
{
  "SecurityKey": {
    "AllowedKeys": ["corporate-api-key"],
    "AllowedNetworks": [
      "10.0.0.0/8",         // Corporate internal network
      "172.16.0.0/12",      // Secondary corporate network
      "203.0.113.0/24"      // Public-facing servers
    ]
  }
}
```


### Reverse Proxy Considerations

When running behind a reverse proxy (like nginx, IIS, or cloud load balancers), ensure proper configuration to get the real client IP:

```csharp
// Configure forwarded headers
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownProxies.Clear();
    options.KnownNetworks.Clear();
});

var app = builder.Build();

// Use forwarded headers before SecurityKey middleware
app.UseForwardedHeaders();
app.UseSecurityKey();
```

### Security Considerations

1. **Combine with HTTPS**: IP whitelisting should always be combined with HTTPS to prevent man-in-the-middle attacks
2. **Network Ranges**: Be careful with broad network ranges like `0.0.0.0/0` or `::/0` as they allow all addresses
3. **Dynamic IPs**: Consider that client IPs may change, especially for mobile clients or users behind NAT
4. **Proxy Headers**: Validate that your reverse proxy configuration correctly forwards real client IPs
5. **Logging**: Monitor failed authentication attempts to detect potential security issues


## Usage Patterns

AspNetCore.SecurityKey supports multiple integration patterns to fit different application architectures and security requirements.

### 1. Middleware Pattern (Global Protection)

Apply API key requirement to all endpoints in your application:

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register services
builder.Services.AddAuthorization();
builder.Services.AddSecurityKey();

var app = builder.Build();

// Apply security to ALL endpoints
app.UseSecurityKey();
app.UseAuthorization();

// All these endpoints require valid API keys
app.MapGet("/weather", () => WeatherService.GetForecast());
app.MapGet("/users", () => UserService.GetUsers()); 
app.MapGet("/products", () => ProductService.GetProducts());

app.Run();
```

### 2. Attribute Pattern (Selective Protection)

Apply API key requirement to specific controllers or actions:

```csharp
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    // This action requires API key
    [SecurityKey]
    [HttpGet]
    public IEnumerable<User> GetUsers()
    {
        return UserService.GetUsers();
    }
    
    // This action is public (no API key required)
    [HttpGet("public")]
    public IEnumerable<User> GetPublicUsers()
    {
        return UserService.GetPublicUsers();
    }
}

// Or apply to entire controller
[SecurityKey]
[ApiController]  
[Route("[controller]")]
public class SecureController : ControllerBase
{
    // All actions in this controller require API key
    [HttpGet]
    public IActionResult Get() => Ok();
}
```

### 3. Endpoint Filter Pattern (Minimal APIs)

Secure specific minimal API endpoints:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();
builder.Services.AddSecurityKey();

var app = builder.Build();

app.UseAuthorization();

// Public endpoint (no API key required)
app.MapGet("/health", () => "Healthy");

// Secured endpoint using filter
app.MapGet("/users", () => UserService.GetUsers())
   .RequireSecurityKey();

// Multiple endpoints can be grouped
var securedGroup = app.MapGroup("/api/secure")
                     .RequireSecurityKey();

securedGroup.MapGet("/data", () => "Secured data");
securedGroup.MapPost("/action", () => "Secured action");

app.Run();
```

### 4. Authentication Scheme Pattern (Full Integration)

Integrate with ASP.NET Core's authentication system:

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register authentication with SecurityKey scheme
builder.Services
    .AddAuthentication()
    .AddSecurityKey();

builder.Services.AddAuthorization();
builder.Services.AddSecurityKey();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Use standard authorization attributes
app.MapGet("/users", () => UserService.GetUsers())
   .RequireAuthorization();

// Can also be combined with role-based authorization
app.MapGet("/admin", () => "Admin data")
   .RequireAuthorization("AdminPolicy");

app.Run();
```

## Advanced Customization

### Custom Security Key Validation

Implement custom validation logic by creating a class that implements `ISecurityKeyValidator`:

```csharp
public class DatabaseSecurityKeyValidator : ISecurityKeyValidator
{
    private readonly IApiKeyRepository _repository;
    private readonly ILogger<DatabaseSecurityKeyValidator> _logger;

    public DatabaseSecurityKeyValidator(
        IApiKeyRepository repository, 
        ILogger<DatabaseSecurityKeyValidator> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    public async ValueTask<bool> Validate(string? value, IPAddress? ipAddress = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        try
        {
            var apiKey = await _repository.GetApiKeyAsync(value, cancellationToken);
            
            if (apiKey == null)
            {
                _logger.LogWarning("Invalid API key attempted: {Key}", value);
                return false;
            }

            if (apiKey.IsExpired)
            {
                _logger.LogWarning("Expired API key used: {Key}", value);
                return false;
            }

            // Validate IP address if restrictions are configured
            if (!IsIpAddressAllowed(ipAddress, apiKey.AllowedIpAddresses, apiKey.AllowedNetworks))
            {
                _logger.LogWarning("API key {Key} used from unauthorized IP: {IpAddress}", value, ipAddress);
                return false;
            }

            // Update last used timestamp
            await _repository.UpdateLastUsedAsync(value, DateTime.UtcNow, cancellationToken);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating API key");
            return false;
        }
    }

    public async ValueTask<ClaimsIdentity> Authenticate(string? value, IPAddress? ipAddress = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(value))
            return new ClaimsIdentity();

        var apiKey = await _repository.GetApiKeyAsync(value, cancellationToken);
        if (apiKey?.User == null)
            return new ClaimsIdentity();

        var identity = new ClaimsIdentity(SecurityKeyAuthenticationDefaults.AuthenticationScheme);        
        identity.AddClaim(new Claim(ClaimTypes.Name, apiKey.User.Name));
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, apiKey.User.Id));
        
        // Add role claims
        foreach (var role in apiKey.User.Roles)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
        }

        return identity;
    }

    private bool IsIpAddressAllowed(IPAddress? ipAddress, string[]? allowedAddresses, string[]? allowedNetworks)
    {
        // Use the built-in whitelist functionality
        return SecurityKeyWhitelist.IsIpAllowed(ipAddress, allowedAddresses, allowedNetworks);
    }
}

// Register custom validator
builder.Services.AddScoped<IApiKeyRepository, ApiKeyRepository>();
builder.Services.AddSecurityKey<DatabaseSecurityKeyValidator>();
```

### Custom Security Key Extraction

Create custom extraction logic for non-standard scenarios:

```csharp
public class CustomSecurityKeyExtractor : ISecurityKeyExtractor
{
    private readonly ILogger<CustomSecurityKeyExtractor> _logger;

    public CustomSecurityKeyExtractor(ILogger<CustomSecurityKeyExtractor> logger)
    {
        _logger = logger;
    }

    public string? GetKey(HttpContext? context)
    {
        if (context == null)
            return null;

        // Try multiple sources in priority order
        
        // 1. Authorization header with Bearer scheme
        if (context.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var auth = authHeader.FirstOrDefault();
            if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return auth.Substring(7); // Remove "Bearer " prefix
            }
        }

        // 2. Custom header
        if (context.Request.Headers.TryGetValue("X-API-TOKEN", out var tokenHeader))
        {
            return tokenHeader.FirstOrDefault();
        }

        // 3. Query parameter
        if (context.Request.Query.TryGetValue("access_token", out var queryToken))
        {
            return queryToken.FirstOrDefault();
        }

        // 4. Form data (for POST requests)
        if (context.Request.HasFormContentType && 
            context.Request.Form.TryGetValue("api_key", out var formKey))
        {
            return formKey.FirstOrDefault();
        }

        _logger.LogDebug("No API key found in request");
        return null;
    }
}

// Register both custom validator and extractor
builder.Services.AddSecurityKey<DatabaseSecurityKeyValidator, CustomSecurityKeyExtractor>();
```

### Rate Limiting Integration

Combine with ASP.NET Core rate limiting for enhanced security:

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("ApiKeyPolicy", context =>
    {
        // Extract API key for rate limiting
        var apiKey = context.Request.Headers["X-API-KEY"].FirstOrDefault();
        
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: apiKey ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            });
    });
});

var app = builder.Build();

app.UseRateLimiter();
app.UseSecurityKey();

app.MapGet("/api/data", () => "Data")
   .RequireRateLimiting("ApiKeyPolicy");
```

## OpenAPI/Swagger Integration

AspNetCore.SecurityKey provides automatic OpenAPI documentation support for .NET 9+ applications.

### Basic OpenAPI Setup

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register authentication
builder.Services
    .AddAuthentication()
    .AddSecurityKey();

builder.Services.AddAuthorization();
builder.Services.AddSecurityKey();

// Add OpenAPI with SecurityKey transformer
builder.Services.AddOpenApi(options => 
    options.AddDocumentTransformer<SecurityKeyDocumentTransformer>());

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Configure endpoints
app.MapGet("/secure-data", () => "This endpoint requires API key")
   .RequireAuthorization()
   .WithOpenApi();

// Expose OpenAPI document
app.MapOpenApi();

// Optional: Use Scalar for API documentation
app.MapScalarApiReference();

app.Run();
```

### Swagger/Swashbuckle Integration (Legacy)

For applications using Swashbuckle.AspNetCore:

```csharp
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Name = "X-API-KEY",
        Description = "API Key needed to access the endpoints"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            Array.Empty<string>()
        }
    });
});
```

The `SecurityKeyDocumentTransformer` automatically configures the OpenAPI specification to include API key authentication requirements, making it easy for developers to understand and test your API.

## Best Practices

### Security Considerations

1. **Use HTTPS**: Always use HTTPS in production to protect API keys in transit
2. **Key Rotation**: Implement regular API key rotation policies
3. **Logging**: Log authentication attempts without exposing the actual keys
4. **Rate Limiting**: Implement rate limiting to prevent abuse
5. **IP Whitelisting**: Use IP restrictions for additional security when possible
6. **Timing Attack Protection**: The library uses cryptographic operations to prevent timing attacks

### Configuration Best Practices

1. **Environment Variables**: Store sensitive keys in environment variables or secure key vaults
2. **Separate Keys**: Use different API keys for different environments (dev, staging, production)
3. **Network Restrictions**: Configure IP whitelisting to restrict access to known sources
4. **Monitor Usage**: Implement logging and monitoring to track API key usage patterns

### Performance Considerations

1. **Caching**: Enable caching for authentication results when using custom validators
2. **Connection Pooling**: Use connection pooling for database-backed validators
3. **Async Operations**: Leverage async/await patterns for I/O operations

## Troubleshooting

### Common Issues

**Issue**: API key not being extracted from requests

**Solution**: Check header/query parameter names match configuration:

```csharp
builder.Services.AddSecurityKey(options =>
{
    options.HeaderName = "X-API-KEY"; // Must match client header
    options.QueryName = "apikey";     // Must match query parameter
});
```

**Issue**: Authentication works but authorization fails

**Solution**: Ensure authentication scheme is properly configured:

```csharp
// For controller attributes
[Authorize(AuthenticationSchemes = SecurityKeyAuthenticationDefaults.AuthenticationScheme)]

// Or set as default scheme
builder.Services
    .AddAuthentication(SecurityKeyAuthenticationDefaults.AuthenticationScheme)
    .AddSecurityKey();
```

**Issue**: Custom validator not being called

**Solution**: Verify registration order and dependencies:

```csharp
// Register dependencies first
builder.Services.AddScoped<IApiKeyRepository, ApiKeyRepository>();
// Then register validator
builder.Services.AddSecurityKey<CustomValidator>();
```

**Issue**: IP whitelisting not working correctly

**Solution**: Check reverse proxy configuration and enable debug logging:

```csharp
// Configure forwarded headers
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

var app = builder.Build();
app.UseForwardedHeaders(); // Must be before UseSecurityKey()
app.UseSecurityKey();
```

### Debug Logging

Enable detailed logging to troubleshoot issues:

```json
{
  "Logging": {
    "LogLevel": {
      "AspNetCore.SecurityKey": "Debug",
      "Microsoft.AspNetCore.Authentication": "Debug"
    }
  }
}
```

## Examples Repository

For complete working examples, see the samples in this repository:

- **[Sample.Controllers](samples/Sample.Controllers/)** - Controller-based API with attribute security
- **[Sample.Middleware](samples/Sample.Middleware/)** - Middleware-based global security  
- **[Sample.MinimalApi](samples/Sample.MinimalApi/)** - Minimal APIs with endpoint filters and IP whitelisting

Each sample includes:

- Complete working application
- Configuration examples
- HTTP test files
- Different authentication patterns

## Contributing

We welcome contributions! Please see our [contributing guidelines](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
