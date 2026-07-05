package graphBetaNetworkWebContentFilteringPolicyRule

import (
	"context"
	"fmt"
	"strings"

	"github.com/deploymenttheory/terraform-provider-microsoft365/internal/services/common/constructors"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	s "github.com/microsoft/kiota-abstractions-go/serialization"
)

func constructResource(ctx context.Context, data *NetworkWebContentFilteringPolicyRuleResourceModel) (s.Parsable, error) {
	tflog.Debug(ctx, fmt.Sprintf("Constructing %s resource from model", ResourceName))

	urlsOrFqdns, err := stringSetValues(ctx, data.UrlsOrFqdns)
	if err != nil {
		return nil, fmt.Errorf("failed to read urls_or_fqdns: %w", err)
	}
	webCategories, err := stringSetValues(ctx, data.WebCategories)
	if err != nil {
		return nil, fmt.Errorf("failed to read web_categories: %w", err)
	}
	httpMethods, err := stringSetValues(ctx, data.HTTPMethods)
	if err != nil {
		return nil, fmt.Errorf("failed to read http_methods: %w", err)
	}
	sessionTypes, err := stringSetValues(ctx, data.SessionTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to read session_types: %w", err)
	}
	customHeaders, err := customHeaderValues(ctx, data.CustomHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom_headers: %w", err)
	}
	if data.Action.ValueString() != "allow" && len(customHeaders) > 0 {
		return nil, fmt.Errorf("custom_headers can only be used when action is allow")
	}

	targets := make([]s.Parsable, 0, 2)
	if len(urlsOrFqdns) > 0 {
		targets = append(targets, &destinationTargetRequestBody{
			odataType: webFilteringURLDestinationODataType,
			values:    urlsOrFqdns,
		})
	}
	if len(webCategories) > 0 {
		targets = append(targets, &destinationTargetRequestBody{
			odataType: webFilteringWebCategoryDestinationODataType,
			values:    webCategories,
		})
	}

	requestBody := &webContentFilteringPolicyRuleRequestBody{
		odataType:   webFilteringRuleODataType,
		name:        data.Name.ValueStringPointer(),
		description: data.Description.ValueStringPointer(),
		action: &actionRequestBody{
			odataType: graphActionODataType(data.Action.ValueString()),
		},
		priority: data.Priority.ValueInt64Pointer(),
		settings: &ruleSettingsRequestBody{
			status: data.Status.ValueStringPointer(),
		},
		matchingConditions: &matchingConditionsRequestBody{
			destinations: &destinationsRequestBody{
				targets:           targets,
				httpRequestMethod: commaStringPointer(httpMethods),
			},
		},
	}

	if len(sessionTypes) > 0 {
		requestBody.matchingConditions.sources = &sourcesRequestBody{
			sessionType: commaStringPointer(sessionTypes),
		}
	}
	if len(customHeaders) > 0 {
		requestBody.customHeaders = customHeaders
	}

	if err := constructors.DebugLogGraphObject(ctx, fmt.Sprintf("Final JSON to be sent to Graph API for resource %s", ResourceName), requestBody); err != nil {
		tflog.Error(ctx, "Failed to debug log object", map[string]any{
			"error": err.Error(),
		})
	}

	return requestBody, nil
}

func stringSetValues(ctx context.Context, value types.Set) ([]string, error) {
	if value.IsNull() || value.IsUnknown() {
		return nil, nil
	}

	var result []string
	diags := value.ElementsAs(ctx, &result, false)
	if diags.HasError() {
		return nil, fmt.Errorf("%s", diags.Errors()[0].Detail())
	}

	return result, nil
}

func customHeaderValues(ctx context.Context, value types.List) ([]s.Parsable, error) {
	if value.IsNull() || value.IsUnknown() {
		return nil, nil
	}

	var headers []customHeaderModel
	diags := value.ElementsAs(ctx, &headers, false)
	if diags.HasError() {
		return nil, fmt.Errorf("%s", diags.Errors()[0].Detail())
	}

	result := make([]s.Parsable, 0, len(headers))
	for _, header := range headers {
		result = append(result, &customHeaderRequestBody{
			headerName:  header.HeaderName.ValueStringPointer(),
			headerValue: header.HeaderValue.ValueStringPointer(),
		})
	}

	return result, nil
}

func commaStringPointer(values []string) *string {
	if len(values) == 0 {
		return nil
	}

	value := strings.Join(values, ", ")
	return &value
}

type webContentFilteringPolicyRuleRequestBody struct {
	odataType          string
	name               *string
	description        *string
	action             *actionRequestBody
	priority           *int64
	settings           *ruleSettingsRequestBody
	matchingConditions *matchingConditionsRequestBody
	customHeaders      []s.Parsable
}

func (b *webContentFilteringPolicyRuleRequestBody) Serialize(writer s.SerializationWriter) error {
	if err := writer.WriteStringValue("@odata.type", &b.odataType); err != nil {
		return err
	}
	if err := writer.WriteStringValue("name", b.name); err != nil {
		return err
	}
	if err := writer.WriteStringValue("description", b.description); err != nil {
		return err
	}
	if err := writer.WriteObjectValue("action", b.action); err != nil {
		return err
	}
	if err := writer.WriteInt64Value("priority", b.priority); err != nil {
		return err
	}
	if err := writer.WriteObjectValue("settings", b.settings); err != nil {
		return err
	}
	if err := writer.WriteObjectValue("matchingConditions", b.matchingConditions); err != nil {
		return err
	}
	if len(b.customHeaders) > 0 {
		if err := writer.WriteCollectionOfObjectValues("customHeaders", b.customHeaders); err != nil {
			return err
		}
	}

	return nil
}

func (b *webContentFilteringPolicyRuleRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type actionRequestBody struct {
	odataType string
}

func (b *actionRequestBody) Serialize(writer s.SerializationWriter) error {
	return writer.WriteStringValue("@odata.type", &b.odataType)
}

func (b *actionRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type ruleSettingsRequestBody struct {
	status *string
}

func (b *ruleSettingsRequestBody) Serialize(writer s.SerializationWriter) error {
	return writer.WriteStringValue("status", b.status)
}

func (b *ruleSettingsRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type matchingConditionsRequestBody struct {
	destinations *destinationsRequestBody
	sources      *sourcesRequestBody
}

func (b *matchingConditionsRequestBody) Serialize(writer s.SerializationWriter) error {
	if err := writer.WriteObjectValue("destinations", b.destinations); err != nil {
		return err
	}
	if b.sources != nil {
		if err := writer.WriteObjectValue("sources", b.sources); err != nil {
			return err
		}
	}

	return nil
}

func (b *matchingConditionsRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type destinationsRequestBody struct {
	targets           []s.Parsable
	httpRequestMethod *string
}

func (b *destinationsRequestBody) Serialize(writer s.SerializationWriter) error {
	if err := writer.WriteCollectionOfObjectValues("targets", b.targets); err != nil {
		return err
	}
	if err := writer.WriteStringValue("httpRequestMethod", b.httpRequestMethod); err != nil {
		return err
	}

	return nil
}

func (b *destinationsRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type destinationTargetRequestBody struct {
	odataType string
	values    []string
}

func (b *destinationTargetRequestBody) Serialize(writer s.SerializationWriter) error {
	if err := writer.WriteStringValue("@odata.type", &b.odataType); err != nil {
		return err
	}
	return writer.WriteCollectionOfStringValues("values", b.values)
}

func (b *destinationTargetRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type sourcesRequestBody struct {
	sessionType *string
}

func (b *sourcesRequestBody) Serialize(writer s.SerializationWriter) error {
	return writer.WriteStringValue("sessionType", b.sessionType)
}

func (b *sourcesRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}

type customHeaderRequestBody struct {
	headerName  *string
	headerValue *string
}

func (b *customHeaderRequestBody) Serialize(writer s.SerializationWriter) error {
	if err := writer.WriteStringValue("headerName", b.headerName); err != nil {
		return err
	}
	return writer.WriteStringValue("headerValue", b.headerValue)
}

func (b *customHeaderRequestBody) GetFieldDeserializers() map[string]func(s.ParseNode) error {
	return map[string]func(s.ParseNode) error{}
}
