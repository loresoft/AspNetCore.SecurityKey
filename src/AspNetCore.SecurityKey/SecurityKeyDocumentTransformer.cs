#if NET9_0_OR_GREATER

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;

namespace AspNetCore.SecurityKey;

/// <summary>
/// A transformer that modifies the OpenAPI document to include security key authentication schemes.
/// </summary>
public class SecurityKeyDocumentTransformer(IAuthenticationSchemeProvider authenticationSchemeProvider, IOptions<SecurityKeyOptions> securityKeyOptions)
    : IOpenApiDocumentTransformer
{
    /// <summary>
    /// Transforms the OpenAPI document to include security key authentication schemes.
    /// </summary>
    /// <param name="document">The OpenAPI document to transform.</param>
    /// <param name="context">The context for the OpenAPI document transformation.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
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
