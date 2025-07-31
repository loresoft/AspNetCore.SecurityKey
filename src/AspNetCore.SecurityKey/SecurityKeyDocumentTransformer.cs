#if NET9_0_OR_GREATER

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Modifies the OpenAPI document to include security API key authentication schemes.
/// This transformer inspects the registered authentication schemes and, if the security API key scheme is present,
/// adds the appropriate <see cref="OpenApiSecurityScheme"/> to the document components and applies it to all operations.
/// </summary>
public class SecurityKeyDocumentTransformer(
    IAuthenticationSchemeProvider authenticationSchemeProvider,
    IOptions<SecurityKeyOptions> securityKeyOptions)
    : IOpenApiDocumentTransformer
{
    /// <summary>
    /// Transforms the provided <see cref="OpenApiDocument"/> to include security API key authentication.
    /// If the security API key authentication scheme is registered, this method adds an <see cref="OpenApiSecurityScheme"/>
    /// using the header name specified in <see cref="SecurityKeyOptions.HeaderName"/> and applies the scheme to all operations.
    /// </summary>
    /// <param name="document">The <see cref="OpenApiDocument"/> to transform.</param>
    /// <param name="context">The <see cref="OpenApiDocumentTransformerContext"/> for the transformation process.</param>
    /// <param name="cancellationToken">A <see cref="CancellationToken"/> to monitor for cancellation requests.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous transformation operation.
    /// </returns>
    public async Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
    {
        var authenticationSchemes = await authenticationSchemeProvider.GetAllSchemesAsync();

        if (!authenticationSchemes.Any(authScheme => string.Equals(authScheme.Name, SecurityKeyAuthenticationDefaults.AuthenticationScheme, StringComparison.InvariantCultureIgnoreCase)))
            return;

        var headerName = securityKeyOptions.Value.HeaderName;

        var openApiSecurityScheme1 = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey,
            Scheme = SecurityKeyAuthenticationDefaults.AuthenticationScheme,
            In = ParameterLocation.Header,
            Name = headerName
        };

        var requirements = new Dictionary<string, OpenApiSecurityScheme>
        {
            ["API Key"] = openApiSecurityScheme1
        };

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes = requirements;

        foreach (var operation in document.Paths.Values.SelectMany(path => path.Operations))
        {
            var openApiSecurityScheme = new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "API Key",
                    Type = ReferenceType.SecurityScheme
                }
            };
            var requirement = new OpenApiSecurityRequirement
            {
                [openApiSecurityScheme] = Array.Empty<string>()
            };

            operation.Value.Security.Add(requirement);
        }
    }
}
#endif
