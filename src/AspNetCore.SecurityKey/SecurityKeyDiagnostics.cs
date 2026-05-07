using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;

namespace AspNetCore.SecurityKey;

/// <summary>
/// Provides stable diagnostics names for SecurityKey authentication tracing and metrics.
/// </summary>
public static class SecurityKeyDiagnostics
{
    /// <summary>
    /// The activity source name used by SecurityKey diagnostics.
    /// </summary>
    public const string SourceName = "AspNetCore.SecurityKey";

    /// <summary>
    /// The meter name used by SecurityKey diagnostics.
    /// </summary>
    public const string MeterName = "AspNetCore.SecurityKey";


    /// <summary>
    /// The authentication request counter name.
    /// </summary>
    public const string AuthenticationRequestsName = "securitykey.auth.requests";

    /// <summary>
    /// The authentication failure counter name.
    /// </summary>
    public const string AuthenticationFailuresName = "securitykey.auth.failures";

    /// <summary>
    /// The authentication duration histogram name.
    /// </summary>
    public const string AuthenticationDurationName = "securitykey.auth.duration";

    /// <summary>
    /// The authentication scheme tag name.
    /// </summary>
    public const string AuthenticationSchemeTagName = "securitykey.auth.scheme";

    /// <summary>
    /// The authentication result tag name.
    /// </summary>
    public const string AuthenticationResultTagName = "securitykey.auth.result";

    /// <summary>
    /// The authentication failure reason tag name.
    /// </summary>
    public const string AuthenticationFailureReasonTagName = "securitykey.auth.failure_reason";

    /// <summary>
    /// The authentication pattern tag name.
    /// </summary>
    public const string AuthenticationPatternTagName = "securitykey.auth.pattern";

    /// <summary>
    /// The tag name for the resolved client.
    /// </summary>
    public const string ClientTagName = "securitykey.client";

    /// <summary>
    /// The tag name for the resolved endpoint.
    /// </summary>
    public const string EndpointTagName = "securitykey.endpoint";

    /// <summary>
    /// The hashed security API key tag name.
    /// </summary>
    public const string SecurityKeyHashTagName = ClientTagName;

    internal const string AuthenticationActivityName = "AspNetCore.SecurityKey.Authenticate";
    internal const string AuthenticationResultSuccess = "success";
    internal const string AuthenticationResultFailure = "failure";
    internal const string InvalidSecurityKeyFailureReason = "invalid_client";
    internal const string AuthenticationErrorFailureReason = "authentication_error";
    internal const string MiddlewareAuthenticationPattern = "middleware";
    internal const string EndpointFilterAuthenticationPattern = "endpoint_filter";
    internal const string MvcFilterAuthenticationPattern = "mvc_filter";

    internal static readonly ActivitySource ActivitySource = new(SourceName, ThisAssembly.FileVersion);
    internal static readonly Meter Meter = new(MeterName, ThisAssembly.FileVersion);

    internal static readonly Counter<long> AuthenticationRequestCounter = Meter.CreateCounter<long>(
        name: AuthenticationRequestsName,
        unit: "{request}",
        description: "Number of SecurityKey authentication attempts.");

    internal static readonly Counter<long> AuthenticationFailureCounter = Meter.CreateCounter<long>(
        name: AuthenticationFailuresName,
        unit: "{failure}",
        description: "Number of failed SecurityKey authentication attempts.");

    internal static readonly Histogram<double> AuthenticationDurationHistogram = Meter.CreateHistogram<double>(
        name: AuthenticationDurationName,
        unit: "ms",
        description: "Duration of SecurityKey authentication attempts.");

    internal static Activity? StartAuthenticationActivity(string pattern)
    {
        var activity = ActivitySource.StartActivity(AuthenticationActivityName, ActivityKind.Server);
        activity?.SetTag(AuthenticationPatternTagName, pattern);

        return activity;
    }

    internal static void CompleteAuthentication(
        Activity? activity,
        long startTimestamp,
        string authenticationResult,
        string? scheme = null,
        string? securityKey = null,
        string? endpoint = null,
        string? failureReason = null)
    {
        if (!string.IsNullOrWhiteSpace(scheme))
            activity?.SetTag(AuthenticationSchemeTagName, scheme);

        activity?.SetTag(AuthenticationResultTagName, authenticationResult);

        var client = ComputeSecurityKeyHash(securityKey);
        if (client is not null)
            activity?.SetTag(ClientTagName, client);

        if (!string.IsNullOrWhiteSpace(endpoint))
            activity?.SetTag(EndpointTagName, endpoint);

        if (failureReason is not null)
            activity?.SetTag(AuthenticationFailureReasonTagName, failureReason);

        if (authenticationResult == AuthenticationResultFailure)
            activity?.SetStatus(ActivityStatusCode.Error, failureReason);

        RecordAuthentication(scheme, authenticationResult, failureReason, startTimestamp, endpoint, client);
    }

    internal static void RecordAuthenticationException(
        Activity? activity,
        long startTimestamp,
        Exception exception,
        string? scheme = null,
        string? securityKey = null,
        string? endpoint = null)
    {
        activity?.AddException(exception);

        CompleteAuthentication(
            activity,
            startTimestamp,
            AuthenticationResultFailure,
            scheme,
            securityKey,
            endpoint,
            failureReason: AuthenticationErrorFailureReason);
    }

    internal static void RecordAuthentication(
        string? scheme,
        string result,
        string? failureReason,
        long startTimestamp,
        string? endpoint = null,
        string? client = null)
    {
        if (!AuthenticationRequestCounter.Enabled &&
            !AuthenticationFailureCounter.Enabled &&
            !AuthenticationDurationHistogram.Enabled)
        {
            return;
        }

        TagList tags =
        [
            new(AuthenticationResultTagName, result)
        ];

        if (!string.IsNullOrWhiteSpace(scheme))
            tags.Add(new(AuthenticationSchemeTagName, scheme));

        if (failureReason is not null)
            tags.Add(new(AuthenticationFailureReasonTagName, failureReason));

        if (!string.IsNullOrWhiteSpace(endpoint))
            tags.Add(new(EndpointTagName, endpoint));

        if (!string.IsNullOrWhiteSpace(client))
            tags.Add(new(ClientTagName, client));

        AuthenticationRequestCounter.Add(1, in tags);

        if (failureReason is not null)
            AuthenticationFailureCounter.Add(1, in tags);

        var elapsed = GetElapsedMilliseconds(startTimestamp);
        AuthenticationDurationHistogram.Record(elapsed, in tags);
    }

    internal static string? ComputeSecurityKeyHash(string? securityKey)
    {
        if (string.IsNullOrWhiteSpace(securityKey))
            return null;

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(securityKey));
        return Convert.ToHexString(hash);
    }

    private static double GetElapsedMilliseconds(long startTimestamp)
        => Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;

}
