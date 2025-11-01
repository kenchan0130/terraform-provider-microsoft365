package client

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/exp/rand"
)

// ConfigureEntraIDClientOptions configures the Entra ID client options based on the provided configuration
func ConfigureEntraIDClientOptions(ctx context.Context, config *ProviderData, authorityURL string) (policy.ClientOptions, error) {
	tflog.Info(ctx, "Starting Entra ID client options configuration")
	tflog.Info(ctx, "Authority URL: "+authorityURL)

	tflog.Info(ctx, "Initializing authentication client options")
	clientOptions := initializeAuthClientOptions(ctx, authorityURL)

	tflog.Info(ctx, "Configuring Retry options")
	configureRetryOptions(ctx, &clientOptions, config)

	tflog.Info(ctx, "Configuring Telemetry options")
	configureTelemetryOptions(ctx, &clientOptions, config)

	tflog.Info(ctx, "Configuring authentication timeout")
	configureAuthTimeout(ctx, &clientOptions, config)

	if config.ClientOptions.UseProxy && config.ClientOptions.ProxyURL != "" {
		tflog.Warn(ctx, "Proxy settings in provider configuration are not applied to Entra ID authentication requests. "+
			"Please rely on HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables if a proxy is required for token acquisition.")
	}

	tflog.Info(ctx, "Using Azure SDK default HTTP client for Entra ID token acquisition")

	tflog.Info(ctx, "Entra ID client options configuration completed successfully")
	return clientOptions, nil
}

func initializeAuthClientOptions(ctx context.Context, authorityURL string) policy.ClientOptions {
	options := policy.ClientOptions{
		Cloud: cloud.Configuration{
			ActiveDirectoryAuthorityHost: authorityURL,
		},
	}
	tflog.Debug(ctx, "Authentication Client options initialized with authority URL: "+authorityURL)
	return options
}

func configureRetryOptions(ctx context.Context, clientOptions *policy.ClientOptions, config *ProviderData) {
	maxRetries := int32(config.ClientOptions.MaxRetries)
	baseDelay := time.Duration(config.ClientOptions.RetryDelaySeconds) * time.Second

	clientOptions.Retry = policy.RetryOptions{
		MaxRetries:    maxRetries,
		RetryDelay:    baseDelay,
		MaxRetryDelay: baseDelay * 10,
		StatusCodes: []int{
			http.StatusRequestTimeout,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout,
		},
		ShouldRetry: func(resp *http.Response, err error) bool {
			if err != nil {
				return true
			}
			if resp == nil {
				return false
			}

			for _, code := range clientOptions.Retry.StatusCodes {
				if resp.StatusCode == code {
					executionCount := resp.Request.Context().Value("RetryCount").(int32)
					exponentialBackoff := baseDelay * time.Duration(math.Pow(2, float64(executionCount)))
					jitter := time.Duration(rand.Int63n(int64(baseDelay)))
					delayWithJitter := exponentialBackoff + jitter

					if delayWithJitter > clientOptions.Retry.MaxRetryDelay {
						delayWithJitter = clientOptions.Retry.MaxRetryDelay
					}

					tflog.Debug(ctx, fmt.Sprintf("Retrying request due to status code %d. Delay with jitter: %v (base: %v, jitter: %v)", resp.StatusCode, delayWithJitter, exponentialBackoff, jitter))

					time.Sleep(delayWithJitter)
					return true
				}
			}
			return false
		},
	}

	tflog.Debug(ctx, fmt.Sprintf("Retry options set: MaxRetries=%d, BaseRetryDelay=%v",
		clientOptions.Retry.MaxRetries, time.Duration(config.ClientOptions.RetryDelaySeconds)*time.Second))
}

func configureTelemetryOptions(ctx context.Context, clientOptions *policy.ClientOptions, config *ProviderData) {
	clientOptions.Telemetry = policy.TelemetryOptions{
		ApplicationID: config.ClientOptions.CustomUserAgent,
		Disabled:      config.TelemetryOptout,
	}
	tflog.Debug(ctx, fmt.Sprintf("Telemetry options set: ApplicationID=%s, Disabled=%t",
		clientOptions.Telemetry.ApplicationID, clientOptions.Telemetry.Disabled))
}

func configureAuthTimeout(ctx context.Context, clientOptions *policy.ClientOptions, config *ProviderData) {
	if config.ClientOptions.TimeoutSeconds > 0 {
		clientOptions.Retry.TryTimeout = time.Duration(config.ClientOptions.TimeoutSeconds) * time.Second
		tflog.Debug(ctx, fmt.Sprintf("Auth timeout set to %v", clientOptions.Retry.TryTimeout))
	} else {
		tflog.Debug(ctx, "No custom auth timeout configured")
	}
}

// configureAuthClientProxy removed: Entra ID token requests now rely on the Azure SDK's default HTTP client.
