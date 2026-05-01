using System.Diagnostics;
using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides an authentication handler for validating requests using a security API key.
/// This handler extracts the API key from the HTTP context and authenticates it using the configured validator.
/// </summary>
public class SecurityKeyAuthenticationHandler : AuthenticationHandler<SecurityKeyAuthenticationSchemeOptions>
{
    private static readonly AuthenticateResult InvalidSecurityKey = AuthenticateResult.Fail("Invalid Security Key");

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityKeyAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor for <see cref="SecurityKeyAuthenticationSchemeOptions"/>.</param>
    /// <param name="logger">The factory for creating <see cref="ILogger"/> instances.</param>
    /// <param name="encoder">The <see cref="UrlEncoder"/> for encoding URLs.</param>
    public SecurityKeyAuthenticationHandler(
        IOptionsMonitor<SecurityKeyAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    { }

    /// <summary>
    /// Handles authentication for the current request by extracting and validating the security API key.
    /// If the key is valid, creates an <see cref="AuthenticationTicket"/> with the authenticated principal.
    /// </summary>
    /// <returns>
    /// An <see cref="AuthenticateResult"/> indicating success or failure of the authentication process.
    /// </returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var startTimestamp = 0L;
        Activity? activity = null;

        try
        {
            // Resolve provider when configured; otherwise use the default registration.
            var keyExtractor = string.IsNullOrEmpty(Options.ProviderServiceKey)
                ? Context.RequestServices.GetRequiredService<ISecurityKeyExtractor>()
                : Context.RequestServices.GetRequiredKeyedService<ISecurityKeyExtractor>(Options.ProviderServiceKey);

            // Extract the security key from the request using the configured extractor
            var securityKey = keyExtractor.GetKey(Context);

            // If no security key is provided, return no result
            if (string.IsNullOrEmpty(securityKey))
                return AuthenticateResult.NoResult();

            startTimestamp = Stopwatch.GetTimestamp();
            activity = SecurityKeyDiagnostics.ActivitySource.StartActivity(SecurityKeyDiagnostics.AuthenticationActivityName, ActivityKind.Server);

            activity?.SetTag(SecurityKeyDiagnostics.AuthenticationSchemeTagName, Scheme.Name);

            var ipAddress = keyExtractor.GetRemoteAddress(Context);

            // Resolve provider when configured; otherwise use the default registration.
            var keyValidator = string.IsNullOrEmpty(Options.ProviderServiceKey)
                ? Context.RequestServices.GetRequiredService<ISecurityKeyValidator>()
                : Context.RequestServices.GetRequiredKeyedService<ISecurityKeyValidator>(Options.ProviderServiceKey);

            // Authenticate the security key and get the claims identity
            var identity = await keyValidator.Authenticate(securityKey, ipAddress, Scheme.Name, Context.RequestAborted);
            var securityKeyHash = SecurityKeyDiagnostics.ComputeSecurityKeyHash(securityKey);

            if (!identity.IsAuthenticated)
            {
                Logger.LogWarning("Invalid security key {SecurityKey} from IP {IPAddress}", securityKey, ipAddress);

                return CompleteAuthentication(
                    result: InvalidSecurityKey,
                    activity: activity,
                    startTimestamp: startTimestamp,
                    authenticationResult: SecurityKeyDiagnostics.AuthenticationResultFailure,
                    securityKeyHash: securityKeyHash,
                    failureReason: SecurityKeyDiagnostics.InvalidSecurityKeyFailureReason);
            }

            // create a user claim for the security key
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return CompleteAuthentication(
                result: AuthenticateResult.Success(ticket),
                activity: activity,
                startTimestamp: startTimestamp,
                authenticationResult: SecurityKeyDiagnostics.AuthenticationResultSuccess,
                securityKeyHash: securityKeyHash);

        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            activity?.AddException(ex);

            CompleteAuthentication(
                result: AuthenticateResult.Fail(ex),
                activity: activity,
                startTimestamp: startTimestamp,
                authenticationResult: SecurityKeyDiagnostics.AuthenticationResultFailure,
                failureReason: SecurityKeyDiagnostics.AuthenticationErrorFailureReason);

            throw;
        }
        finally
        {
            activity?.Dispose();
        }
    }

    private static AuthenticateResult CompleteAuthentication(
        AuthenticateResult result,
        Activity? activity,
        long startTimestamp,
        string authenticationResult,
        string? securityKeyHash = null,
        string? failureReason = null)
    {
        activity?.SetTag(SecurityKeyDiagnostics.AuthenticationResultTagName, authenticationResult);

        if (securityKeyHash is not null)
            activity?.SetTag(SecurityKeyDiagnostics.SecurityKeyHashTagName, securityKeyHash);

        if (failureReason is not null)
            activity?.SetTag(SecurityKeyDiagnostics.AuthenticationFailureReasonTagName, failureReason);

        if (authenticationResult == SecurityKeyDiagnostics.AuthenticationResultFailure)
            activity?.SetStatus(ActivityStatusCode.Error, failureReason);

        SecurityKeyDiagnostics.RecordAuthenticationMetrics(
            startTimestamp: startTimestamp,
            authenticationResult: authenticationResult,
            failureReason: failureReason,
            securityKeyHash: securityKeyHash);

        return result;
    }
}
