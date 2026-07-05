package graphBetaNetworkWebContentFilteringPolicyRule

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	s "github.com/microsoft/kiota-abstractions-go/serialization"
	"github.com/microsoft/kiota-abstractions-go/store"
	jsonserialization "github.com/microsoft/kiota-serialization-json-go"
)

func TestNewWebContentFilteringPolicyRuleRequestInformationSerializesObservedPortalPayload(t *testing.T) {
	ctx := context.Background()
	urlsOrFqdns, diags := types.SetValueFrom(ctx, types.StringType, []string{"*.example.com"})
	if diags.HasError() {
		t.Fatalf("failed to build urls_or_fqdns set: %s", diags.Errors()[0].Detail())
	}
	webCategories, diags := types.SetValueFrom(ctx, types.StringType, []string{"AlcoholAndTobacco"})
	if diags.HasError() {
		t.Fatalf("failed to build web_categories set: %s", diags.Errors()[0].Detail())
	}
	httpMethods, diags := types.SetValueFrom(ctx, types.StringType, []string{"get"})
	if diags.HasError() {
		t.Fatalf("failed to build http_methods set: %s", diags.Errors()[0].Detail())
	}
	sessionTypes, diags := types.SetValueFrom(ctx, types.StringType, []string{"user", "agent"})
	if diags.HasError() {
		t.Fatalf("failed to build session_types set: %s", diags.Errors()[0].Detail())
	}

	body, err := constructResource(ctx, &NetworkWebContentFilteringPolicyRuleResourceModel{
		Name:          types.StringValue("sample-rule-for-codex"),
		Description:   types.StringValue("sample rule for codex"),
		Action:        types.StringValue("allow"),
		Priority:      types.Int64Value(100),
		Status:        types.StringValue("enabled"),
		UrlsOrFqdns:   urlsOrFqdns,
		WebCategories: webCategories,
		HTTPMethods:   httpMethods,
		SessionTypes:  sessionTypes,
	})
	if err != nil {
		t.Fatalf("constructResource returned error: %v", err)
	}

	requestInfo, err := newWebContentFilteringPolicyRuleRequestInformation(
		ctx,
		webContentFilteringPolicyRuleTestRequestAdapter{},
		abstractions.POST,
		"05bd8400-14ae-4eb0-b7d7-339cd312d8f2",
		"",
		body,
	)
	if err != nil {
		t.Fatalf("newWebContentFilteringPolicyRuleRequestInformation returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(requestInfo.Content, &payload); err != nil {
		t.Fatalf("failed to unmarshal request content: %v", err)
	}

	if payload["@odata.type"] != webFilteringRuleODataType {
		t.Fatalf("@odata.type = %#v, expected %#v", payload["@odata.type"], webFilteringRuleODataType)
	}
	action := payload["action"].(map[string]any)
	if action["@odata.type"] != webFilteringActionAllowODataType {
		t.Fatalf("action @odata.type = %#v, expected %#v", action["@odata.type"], webFilteringActionAllowODataType)
	}
	settings := payload["settings"].(map[string]any)
	if settings["status"] != "enabled" {
		t.Fatalf("settings.status = %#v, expected enabled", settings["status"])
	}

	matchingConditions := payload["matchingConditions"].(map[string]any)
	destinations := matchingConditions["destinations"].(map[string]any)
	if destinations["httpRequestMethod"] != "get" {
		t.Fatalf("httpRequestMethod = %#v, expected get", destinations["httpRequestMethod"])
	}
	targets := destinations["targets"].([]any)
	if len(targets) != 2 {
		t.Fatalf("targets length = %d, expected 2", len(targets))
	}
	urlTarget := targets[0].(map[string]any)
	if urlTarget["@odata.type"] != webFilteringURLDestinationODataType {
		t.Fatalf("url target @odata.type = %#v, expected %#v", urlTarget["@odata.type"], webFilteringURLDestinationODataType)
	}
	if urlTarget["values"].([]any)[0] != "*.example.com" {
		t.Fatalf("url target value = %#v, expected *.example.com", urlTarget["values"].([]any)[0])
	}
	categoryTarget := targets[1].(map[string]any)
	if categoryTarget["@odata.type"] != webFilteringWebCategoryDestinationODataType {
		t.Fatalf("category target @odata.type = %#v, expected %#v", categoryTarget["@odata.type"], webFilteringWebCategoryDestinationODataType)
	}
	if categoryTarget["values"].([]any)[0] != "AlcoholAndTobacco" {
		t.Fatalf("category value = %#v, expected AlcoholAndTobacco", categoryTarget["values"].([]any)[0])
	}
	sources := matchingConditions["sources"].(map[string]any)
	if sources["sessionType"] != "user, agent" {
		t.Fatalf("sessionType = %#v, expected user, agent", sources["sessionType"])
	}
}

type webContentFilteringPolicyRuleTestRequestAdapter struct{}

func (webContentFilteringPolicyRuleTestRequestAdapter) Send(context.Context, *abstractions.RequestInformation, s.ParsableFactory, abstractions.ErrorMappings) (s.Parsable, error) {
	return nil, nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SendEnum(context.Context, *abstractions.RequestInformation, s.EnumFactory, abstractions.ErrorMappings) (any, error) {
	return nil, nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SendCollection(context.Context, *abstractions.RequestInformation, s.ParsableFactory, abstractions.ErrorMappings) ([]s.Parsable, error) {
	return nil, nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SendEnumCollection(context.Context, *abstractions.RequestInformation, s.EnumFactory, abstractions.ErrorMappings) ([]any, error) {
	return nil, nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SendPrimitive(context.Context, *abstractions.RequestInformation, string, abstractions.ErrorMappings) (any, error) {
	return nil, nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SendPrimitiveCollection(context.Context, *abstractions.RequestInformation, string, abstractions.ErrorMappings) ([]any, error) {
	return nil, nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SendNoContent(context.Context, *abstractions.RequestInformation, abstractions.ErrorMappings) error {
	return nil
}

func (webContentFilteringPolicyRuleTestRequestAdapter) GetSerializationWriterFactory() s.SerializationWriterFactory {
	return jsonserialization.NewJsonSerializationWriterFactory()
}

func (webContentFilteringPolicyRuleTestRequestAdapter) EnableBackingStore(store.BackingStoreFactory) {
}

func (webContentFilteringPolicyRuleTestRequestAdapter) SetBaseUrl(string) {}

func (webContentFilteringPolicyRuleTestRequestAdapter) GetBaseUrl() string {
	return "https://graph.microsoft.com/beta"
}

func (webContentFilteringPolicyRuleTestRequestAdapter) ConvertToNativeRequest(context.Context, *abstractions.RequestInformation) (any, error) {
	return nil, nil
}
