# AspNetCore.SecurityKey Samples

This directory contains complete working examples demonstrating different usage patterns of AspNetCore.SecurityKey.

## Sample Applications

### [Sample.Controllers](Sample.Controllers/)

**Pattern**: Controller-based API with attribute security  
**Best for**: Traditional MVC applications, selective endpoint protection

This sample demonstrates:

- Using `[SecurityKey]` attribute on controllers and actions
- Mixing secured and public endpoints
- Integration with Swagger/OpenAPI
- Custom configuration path

**Key Files**:

- `Program.cs` - Basic setup with custom configuration
- `Controllers/UserController.cs` - Class-level security
- `Controllers/AddressController.cs` - Action-level security
- `Controllers/WeatherController.cs` - Public controller (no security)

### [Sample.Middleware](Sample.Middleware/)

**Pattern**: Middleware-based global security  
**Best for**: APIs where all endpoints should be secured by default

This sample demonstrates:

- Global API key requirement using `app.UseSecurityKey()`
- Minimal API endpoints
- All endpoints protected automatically
- Basic configuration

**Key Files**:

- `Program.cs` - Middleware setup protecting all endpoints

### [Sample.MinimalApi](Sample.MinimalApi/)

**Pattern**: Minimal APIs with selective endpoint filters  
**Best for**: Modern minimal APIs with fine-grained security control

This sample demonstrates:

- Mixed authentication schemes (SecurityKey + Authorization)
- Endpoint-specific security using `.RequireSecurityKey()`
- Claims-based authentication
- OpenAPI integration with Scalar documentation
- Different security patterns on different endpoints

**Key Files**:

- `Program.cs` - Multiple authentication patterns
- Shows both `.RequireSecurityKey()` and `.RequireAuthorization()`

## Configuration Files

Each sample includes:

- `appsettings.json` - API key configuration
- `*.http` - HTTP test files for manual testing
- Project files with necessary dependencies

## Running the Samples

1. Navigate to any sample directory:

   ```bash
   cd samples/Sample.MinimalApi
   ```

2. Run the application:

   ```bash
   dotnet run
   ```

3. Test with provided HTTP files or use curl:

   ```bash
   curl -H "X-API-KEY: 01HSGVBSF99SK6XMJQJYF0X3WQ" https://localhost:7216/users
   ```

## API Keys for Testing

All samples use these test API keys (configured in `appsettings.json`):

- `01HSGVBGWXWDWTFGTJSYFXXDXQ`
- `01HSGVBSF99SK6XMJQJYF0X3WQ`
- `01HSGVAH2M5WVQYG4YPT7FNK4K8`

## Sample Comparison

| Feature | Controllers | Middleware | MinimalApi |
|---------|-------------|------------|------------|
| Granular Control | ✅ | ❌ | ✅ |
| Global Security | ❌ | ✅ | ❌ |
| Mixed Auth | ✅ | ❌ | ✅ |
| OpenAPI | ✅ | ✅ | ✅ |
| Claims Support | ❌ | ❌ | ✅ |

Choose the pattern that best fits your application architecture and security requirements.
