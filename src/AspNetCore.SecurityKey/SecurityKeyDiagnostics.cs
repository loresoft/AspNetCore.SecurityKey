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
    public const string ActivitySourceName = "AspNetCore.SecurityKey";

    /// <summary>
    /// The meter name used by SecurityKey diagnostics.
    /// </summary>
    public const string MeterName = "AspNetCore.SecurityKey";


    /// <summary>
    /// The authentication request counter name.
    /// </summary>
    public const string AuthenticationRequestCounterName = "securitykey.authentication.requests";

    /// <summary>
    /// The authentication failure counter name.
    /// </summary>
    public const string AuthenticationFailureCounterName = "securitykey.authentication.failures";

    /// <summary>
    /// The authentication duration histogram name.
    /// </summary>
    public const string AuthenticationDurationHistogramName = "securitykey.authentication.duration";

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
    /// The hashed security API key tag name.
    /// </summary>
    public const string SecurityKeyHashTagName = "securitykey.api_key.hash";

    internal const string AuthenticationActivityName = "AspNetCore.SecurityKey.Authenticate";
    internal const string AuthenticationResultSuccess = "success";
    internal const string AuthenticationResultFailure = "failure";
    internal const string InvalidSecurityKeyFailureReason = "invalid_client";
    internal const string AuthenticationErrorFailureReason = "authentication_error";
    internal const string MiddlewareAuthenticationPattern = "middleware";
    internal const string EndpointFilterAuthenticationPattern = "endpoint_filter";
    internal const string MvcFilterAuthenticationPattern = "mvc_filter";

    internal static readonly ActivitySource ActivitySource = new(ActivitySourceName, ThisAssembly.FileVersion);
    internal static readonly Meter Meter = new(MeterName, ThisAssembly.FileVersion);

    internal static readonly Counter<long> AuthenticationRequestCounter = Meter.CreateCounter<long>(
        name: AuthenticationRequestCounterName,
        unit: "requests",
        description: "Number of SecurityKey authentication requests handled.");

    internal static readonly Counter<long> AuthenticationFailureCounter = Meter.CreateCounter<long>(
        name: AuthenticationFailureCounterName,
        unit: "failures",
        description: "Number of failed SecurityKey authentication requests.");

    internal static readonly Histogram<double> AuthenticationDurationHistogram = Meter.CreateHistogram<double>(
        name: AuthenticationDurationHistogramName,
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
        string? securityKey = null,
        string? failureReason = null)
    {
        activity?.SetTag(AuthenticationResultTagName, authenticationResult);

        var securityKeyHash = ComputeSecurityKeyHash(securityKey);
        if (securityKeyHash is not null)
            activity?.SetTag(SecurityKeyHashTagName, securityKeyHash);

        if (failureReason is not null)
            activity?.SetTag(AuthenticationFailureReasonTagName, failureReason);

        if (authenticationResult == AuthenticationResultFailure)
            activity?.SetStatus(ActivityStatusCode.Error, failureReason);

        RecordAuthenticationMetrics(startTimestamp, authenticationResult, failureReason, securityKeyHash);
    }

    internal static void RecordAuthenticationException(
        Activity? activity,
        long startTimestamp,
        Exception exception)
    {
        activity?.AddException(exception);

        CompleteAuthentication(
            activity,
            startTimestamp,
            AuthenticationResultFailure,
            AuthenticationErrorFailureReason);
    }

    internal static void RecordAuthenticationMetrics(
        long startTimestamp,
        string authenticationResult,
        string? failureReason,
        string? securityKeyHash = null)
    {
        if (!AuthenticationRequestCounter.Enabled
            && !AuthenticationFailureCounter.Enabled
            && !AuthenticationDurationHistogram.Enabled)
        {
            return;
        }

        var tags = new TagList
        {
            { AuthenticationResultTagName, authenticationResult }
        };

        if (failureReason is not null)
            tags.Add(AuthenticationFailureReasonTagName, failureReason);

        if (securityKeyHash is not null)
            tags.Add(SecurityKeyHashTagName, securityKeyHash);

        if (AuthenticationRequestCounter.Enabled)
            AuthenticationRequestCounter.Add(1, tags);

        if (authenticationResult == AuthenticationResultFailure
            && AuthenticationFailureCounter.Enabled)
        {
            AuthenticationFailureCounter.Add(1, tags);
        }

        if (AuthenticationDurationHistogram.Enabled)
        {
            var totalMilliseconds = Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;
            AuthenticationDurationHistogram.Record(totalMilliseconds, tags);
        }
    }

    internal static string? ComputeSecurityKeyHash(string? securityKey)
    {
        if (string.IsNullOrWhiteSpace(securityKey))
            return null;

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(securityKey));
        return Convert.ToHexString(hash);
    }

}
