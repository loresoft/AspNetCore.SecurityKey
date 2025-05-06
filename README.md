# Security API Keys for ASP.NET Core

API Key Authentication Implementation for ASP.NET Core

[![Build Project](https://github.com/loresoft/AspNetCore.SecurityKey/actions/workflows/dotnet.yml/badge.svg)](https://github.com/loresoft/AspNetCore.SecurityKey/actions/workflows/dotnet.yml)

[![Coverage Status](https://coveralls.io/repos/github/loresoft/AspNetCore.SecurityKey/badge.svg?branch=main)](https://coveralls.io/github/loresoft/AspNetCore.SecurityKey?branch=main)

[![AspNetCore.SecurityKey](https://img.shields.io/nuget/v/AspNetCore.SecurityKey.svg)](https://www.nuget.org/packages/AspNetCore.SecurityKey/)


## Passing API Key in a Request

- Request Headers
- Query Parameters
- Cookie

### Request Header

Example passing the security api key via a header

```
GET http://localhost:5009/users
Accept: application/json
X-API-KEY: 01HSGVBSF99SK6XMJQJYF0X3WQ
```

### Query Parameters


Example passing the security api key via a header

```
GET http://localhost:5009/users?X-API-KEY=01HSGVBSF99SK6XMJQJYF0X3WQ
Accept: application/json
```

## Security API Key Setup

### Set the Security API Key

Security API key in the appsetting.json

```json
{
  "SecurityKey": "01HSGVBSF99SK6XMJQJYF0X3WQ"
}
```

Multiple keys supported via semicolon delimiter


```json
{
  "SecurityKey": "01HSGVBGWXWDWTFGTJSYFXXDXQ;01HSGVBSF99SK6XMJQJYF0X3WQ"
}
```

### Register Services

```c#
var builder = WebApplication.CreateBuilder(args);

// add security api key scheme
builder.Services
    .AddAuthentication()
    .AddSecurityKey(); 

builder.Services.AddAuthorization();

// add security api key services
builder.Services.AddSecurityKey();
  
```

Configure Options

```c#
builder.Services.AddSecurityKey(options => {
    options.ConfigurationName = "Authentication:ApiKey";
    options.HeaderName = "x-api-key";
    options.QueryName = "ApiKey";
    options.KeyComparer = StringComparer.OrdinalIgnoreCase;
});
```

### Secure Endpoints

Secure Controller with `SecurityKeyAttribute`.  Can be at class or method level

```c#
[ApiController]
[Route("[controller]")]
public class AddressController : ControllerBase
{
    [SecurityKey]
    [HttpGet(Name = "GetAddresses")]
    public IEnumerable<Address> Get()
    {
        return AddressFaker.Instance.Generate(5);
    }

}
```

Secure via middleware.  All endpoints will require security API key

```c#
public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddAuthorization();
        builder.Services.AddSecurityKey();
        
        var app = builder.Build();
    
        // required api key for all end points
        app.UseSecurityKey();
        app.UseAuthorization();

        app.MapGet("/weather", () => WeatherFaker.Instance.Generate(5));

        app.Run();
    }
}
```

Secure Minimal API endpoint with filter, .NET 8+ only

```c#
public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddAuthorization();
        builder.Services.AddSecurityKey();
        
        var app = builder.Build();
    
        app.UseAuthorization();

        app.MapGet("/users", () => UserFaker.Instance.Generate(10))
            .RequireSecurityKey();

        app.Run();
    }
}
```

Secure with Authentication Scheme

```c#
public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services
            .AddAuthentication()
            .AddSecurityKey();

        builder.Services.AddAuthorization();
        builder.Services.AddSecurityKey();
        
        var app = builder.Build();
    
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/users", () => UserFaker.Instance.Generate(10))
            .RequireAuthorization();

        app.Run();
    }
}
```

### Custom Security Key Validation

You can implement your own custom security key validation by implementing the `ISecurityKeyValidator` interface.

```c#
public class CustomSecurityKeyValidator : ISecurityKeyValidator
{
    public Task<bool> ValidateAsync(HttpContext context, string key)
    {
        // custom validation logic
        return Task.FromResult(true);
    }
}
```

Use custom security key validator

```c#
builder.Services.AddSecurityKey<CustomSecurityKeyValidator>();
```

### Custom Security Key Extractor

You can implement your own custom security key extractor by implementing the `ISecurityKeyExtractor` interface.

```c#
public class CustomSecurityKeyExtractor : ISecurityKeyExtractor
{
    public Task<string> ExtractAsync(HttpContext context)
    {
        // custom extraction logic
        return Task.FromResult("custom-key");
    }
}
```

Use custom security key validator and extrator

```c#
builder.Services.AddSecurityKey<CustomSecurityKeyValidator, CustomSecurityKeyExtractor>();
```

### Open API 

NuGet Package: `AspNetCore.SecurityKey.OpenApi`

Add Open API support 

```c#
var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication()
    .AddSecurityKey();

builder.Services.AddAuthorization();
builder.Services.AddSecurityKey();

// add api key requirment to open api
builder.Services.AddOpenApi(options => options
    .AddDocumentTransformer<SecurityKeyDocumentTransformer>()
);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapOpenApi();

// use Scalar.AspNetCore package 
app.MapScalarApiReference();
```
