using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.SecurityKey.Tests;

public class SecurityKeyDiagnosticsTests
{
    private const string AuthenticationActivityName = "AspNetCore.SecurityKey.Authenticate";
    private const string AuthenticationResultSuccess = "success";
    private const string AuthenticationResultFailure = "failure";
    private const string InvalidSecurityKeyFailureReason = "invalid_client";
    private const string AuthenticationErrorFailureReason = "authentication_error";
    private const string Endpoint = "/diagnostics";

    [Fact]
    public async Task HandleAuthenticateAsync_MissingSecurityKey_DoesNotEmitActivity()
    {
        var activities = await AuthenticateWithActivityListener(new());

        Assert.Empty(activities.Activities);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_DifferentAuthenticationScheme_DoesNotEmitActivity()
    {
        var context = new SecurityKeyAuthenticationHandlerTestContext();
        context.HttpContext.Request.Headers.Authorization = "Bearer token";

        var activities = await AuthenticateWithActivityListener(context);

        Assert.Empty(activities.Activities);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidSecurityKey_EmitsSuccessActivity()
    {
        const string securityKey = "valid-key";

        var context = new SecurityKeyAuthenticationHandlerTestContext { IsAuthenticated = true };
        context.HttpContext.Request.Headers.Append(context.Options.HeaderName, securityKey);

        var activities = await AuthenticateWithActivityListener(context);

        var activity = Assert.Single(activities.Activities);

        Assert.Equal(AuthenticationActivityName, activity.OperationName);
        Assert.Equal(AuthenticationResultSuccess, GetTagValue(activity, SecurityKeyDiagnostics.AuthenticationResultTagName));
        Assert.Equal(SecurityKeyAuthenticationDefaults.AuthenticationScheme, GetTagValue(activity, SecurityKeyDiagnostics.AuthenticationSchemeTagName));
        Assert.Equal(ComputeSecurityKeyHash(securityKey), GetTagValue(activity, SecurityKeyDiagnostics.ClientTagName));
        Assert.Equal(Endpoint, GetTagValue(activity, SecurityKeyDiagnostics.EndpointTagName));
        Assert.DoesNotContain(activity.TagObjects, tag => tag.Value as string == securityKey);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidSecurityKey_EmitsFailureActivity()
    {
        const string securityKey = "invalid-key";

        var context = new SecurityKeyAuthenticationHandlerTestContext();
        context.HttpContext.Request.Headers.Append(context.Options.HeaderName, securityKey);

        var activities = await AuthenticateWithActivityListener(context);

        var activity = Assert.Single(activities.Activities);

        Assert.Equal(AuthenticationResultFailure, GetTagValue(activity, SecurityKeyDiagnostics.AuthenticationResultTagName));
        Assert.Equal(InvalidSecurityKeyFailureReason, GetTagValue(activity, SecurityKeyDiagnostics.AuthenticationFailureReasonTagName));
        Assert.Equal(ComputeSecurityKeyHash(securityKey), GetTagValue(activity, SecurityKeyDiagnostics.ClientTagName));
        Assert.Equal(Endpoint, GetTagValue(activity, SecurityKeyDiagnostics.EndpointTagName));
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_AuthenticationError_EmitsFailureActivity()
    {
        var context = new SecurityKeyAuthenticationHandlerTestContext { AuthenticationException = new InvalidOperationException("Authentication failed.") };
        context.HttpContext.Request.Headers.Append(context.Options.HeaderName, "valid-key");

        var activities = await AuthenticateWithActivityListener(context);

        var activity = Assert.Single(activities.Activities);

        Assert.Equal(AuthenticationResultFailure, GetTagValue(activity, SecurityKeyDiagnostics.AuthenticationResultTagName));
        Assert.Equal(AuthenticationErrorFailureReason, GetTagValue(activity, SecurityKeyDiagnostics.AuthenticationFailureReasonTagName));
        Assert.Equal(Endpoint, GetTagValue(activity, SecurityKeyDiagnostics.EndpointTagName));
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RecordsAuthenticationRequestMetrics()
    {
        const string securityKey = "valid-key";

        var context = new SecurityKeyAuthenticationHandlerTestContext { IsAuthenticated = true };
        context.HttpContext.Request.Headers.Append(context.Options.HeaderName, securityKey);

        var measurements = await AuthenticateWithMeterListener(context);

        var request = Assert.Single(measurements, m => m.InstrumentName == SecurityKeyDiagnostics.AuthenticationRequestsName);

        Assert.Equal(1, request.Value);
        Assert.Equal(SecurityKeyAuthenticationDefaults.AuthenticationScheme, request.Tags[SecurityKeyDiagnostics.AuthenticationSchemeTagName]);
        Assert.Equal(AuthenticationResultSuccess, request.Tags[SecurityKeyDiagnostics.AuthenticationResultTagName]);
        Assert.Equal(ComputeSecurityKeyHash(securityKey), request.Tags[SecurityKeyDiagnostics.ClientTagName]);
        Assert.Equal(Endpoint, request.Tags[SecurityKeyDiagnostics.EndpointTagName]);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RecordsAuthenticationFailureMetrics()
    {
        const string securityKey = "invalid-key";

        var context = new SecurityKeyAuthenticationHandlerTestContext();
        context.HttpContext.Request.Headers.Append(context.Options.HeaderName, securityKey);

        var measurements = await AuthenticateWithMeterListener(context);

        var request = Assert.Single(measurements, m => m.InstrumentName == SecurityKeyDiagnostics.AuthenticationRequestsName);

        Assert.Equal(SecurityKeyAuthenticationDefaults.AuthenticationScheme, request.Tags[SecurityKeyDiagnostics.AuthenticationSchemeTagName]);
        Assert.Equal(AuthenticationResultFailure, request.Tags[SecurityKeyDiagnostics.AuthenticationResultTagName]);
        Assert.Equal(InvalidSecurityKeyFailureReason, request.Tags[SecurityKeyDiagnostics.AuthenticationFailureReasonTagName]);
        Assert.Equal(ComputeSecurityKeyHash(securityKey), request.Tags[SecurityKeyDiagnostics.ClientTagName]);
        Assert.Equal(Endpoint, request.Tags[SecurityKeyDiagnostics.EndpointTagName]);

        var failure = Assert.Single(measurements, m => m.InstrumentName == SecurityKeyDiagnostics.AuthenticationFailuresName);

        Assert.Equal(1, failure.Value);
        Assert.Equal(SecurityKeyAuthenticationDefaults.AuthenticationScheme, failure.Tags[SecurityKeyDiagnostics.AuthenticationSchemeTagName]);
        Assert.Equal(AuthenticationResultFailure, failure.Tags[SecurityKeyDiagnostics.AuthenticationResultTagName]);
        Assert.Equal(InvalidSecurityKeyFailureReason, failure.Tags[SecurityKeyDiagnostics.AuthenticationFailureReasonTagName]);
        Assert.Equal(ComputeSecurityKeyHash(securityKey), failure.Tags[SecurityKeyDiagnostics.ClientTagName]);
        Assert.Equal(Endpoint, failure.Tags[SecurityKeyDiagnostics.EndpointTagName]);
    }

    private static async Task<ActivityCollector> AuthenticateWithActivityListener(SecurityKeyAuthenticationHandlerTestContext context)
    {
        using var collector = new ActivityCollector();

        await AuthenticateAsync(context);

        return collector;
    }

    private static async Task<List<MetricMeasurement>> AuthenticateWithMeterListener(SecurityKeyAuthenticationHandlerTestContext context)
    {
        var measurements = new List<MetricMeasurement>();
        using var listener = new MeterListener();

        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == SecurityKeyDiagnostics.MeterName)
                meterListener.EnableMeasurementEvents(instrument);
        };

        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
            measurements.Add(new MetricMeasurement(instrument.Name, measurement, ToDictionary(tags)))
        );

        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
            measurements.Add(new MetricMeasurement(instrument.Name, measurement, ToDictionary(tags)))
        );

        listener.Start();

        await AuthenticateAsync(context);

        listener.RecordObservableInstruments();

        return measurements;
    }

    private static async Task AuthenticateAsync(SecurityKeyAuthenticationHandlerTestContext context)
    {
        context.HttpContext.Request.Path = Endpoint;

        var services = new ServiceCollection()
            .AddSingleton<ISecurityKeyExtractor>(new TestSecurityKeyExtractor(context.Options))
            .AddSingleton<ISecurityKeyValidator>(new TestSecurityKeyValidator(context))
            .BuildServiceProvider();

        context.HttpContext.RequestServices = services;

        var handler = new SecurityKeyAuthenticationHandler(
            new OptionsMonitor(context.AuthenticationOptions),
            NullLoggerFactory.Instance,
            UrlEncoder.Default);

        AuthenticationScheme scheme = new(SecurityKeyAuthenticationDefaults.AuthenticationScheme, null, typeof(SecurityKeyAuthenticationHandler));

        await handler.InitializeAsync(
            scheme: scheme,
            context: context.HttpContext);

        await handler.AuthenticateAsync();
    }

    private static object? GetTagValue(Activity activity, string key)
        => activity.TagObjects.SingleOrDefault(tag => tag.Key == key).Value;

    private static string ComputeSecurityKeyHash(string securityKey)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(securityKey));
        return Convert.ToHexString(hash);
    }

    private static Dictionary<string, object?> ToDictionary(ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var dictionary = new Dictionary<string, object?>();
        foreach (var tag in tags)
            dictionary[tag.Key] = tag.Value;

        return dictionary;
    }

    private sealed class ActivityCollector : IDisposable
    {
        private readonly ActivityListener _listener;

        public ActivityCollector()
        {
            Activities = [];

            _listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == SecurityKeyDiagnostics.SourceName,
                Sample = (ref _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = activity => Activities.Add(activity)
            };

            ActivitySource.AddActivityListener(_listener);
        }

        public ConcurrentBag<Activity> Activities { get; }

        public void Dispose()
            => _listener.Dispose();
    }

    private sealed record MetricMeasurement(
        string InstrumentName,
        double Value,
        Dictionary<string, object?> Tags
    );

    private sealed class SecurityKeyAuthenticationHandlerTestContext
    {
        public DefaultHttpContext HttpContext { get; } = new();

        public SecurityKeyOptions Options { get; } = new();

        public SecurityKeyAuthenticationSchemeOptions AuthenticationOptions { get; } = new();

        public bool IsAuthenticated { get; set; }

        public Exception? AuthenticationException { get; set; }
    }

    private sealed class TestSecurityKeyExtractor(SecurityKeyOptions options) : ISecurityKeyExtractor
    {
        public string? GetKey(HttpContext? context)
        {
            if (context?.Request.Headers.TryGetValue(options.HeaderName, out var headerKey) == true)
                return headerKey;

            return null;
        }

        public IPAddress? GetRemoteAddress(HttpContext? context)
            => context?.Connection.RemoteIpAddress;
    }

    private sealed class TestSecurityKeyValidator(SecurityKeyAuthenticationHandlerTestContext context) : ISecurityKeyValidator
    {
        public ValueTask<bool> Validate(string? value, IPAddress? ipAddress = null, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(context.IsAuthenticated);

        public ValueTask<ClaimsIdentity> Authenticate(
            string? value,
            IPAddress? ipAddress = null,
            string? scheme = null,
            CancellationToken cancellationToken = default)
        {
            if (context.AuthenticationException is not null)
                throw context.AuthenticationException;

            return ValueTask.FromResult(context.IsAuthenticated
                ? new ClaimsIdentity([new Claim(ClaimTypes.Name, "SecurityKey")], scheme)
                : new ClaimsIdentity());
        }
    }

    private sealed class OptionsMonitor(SecurityKeyAuthenticationSchemeOptions options)
        : IOptionsMonitor<SecurityKeyAuthenticationSchemeOptions>
    {
        public SecurityKeyAuthenticationSchemeOptions CurrentValue => options;

        public SecurityKeyAuthenticationSchemeOptions Get(string? name)
            => options;

        public IDisposable? OnChange(Action<SecurityKeyAuthenticationSchemeOptions, string?> listener)
            => null;
    }
}
