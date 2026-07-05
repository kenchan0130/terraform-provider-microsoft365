package graphBetaNetworkWebContentFilteringPolicyRule

import (
	"context"
	"fmt"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	s "github.com/microsoft/kiota-abstractions-go/serialization"
	"github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
)

const (
	webContentFilteringPolicyRulesURLTemplate    = "{+baseurl}/networkaccess/webFilteringPolicies/{webContentFilteringPolicyId}/policyRules"
	webContentFilteringPolicyRuleItemURLTemplate = webContentFilteringPolicyRulesURLTemplate + "/{policyRuleId}"
)

var webContentFilteringPolicyRuleErrorMapping = abstractions.ErrorMappings{
	"XXX": odataerrors.CreateODataErrorFromDiscriminatorValue,
}

func (r *NetworkWebContentFilteringPolicyRuleResource) createWebContentFilteringPolicyRule(ctx context.Context, policyID string, requestBody s.Parsable) (*webContentFilteringPolicyRuleResponse, error) {
	adapter := r.client.GetAdapter()
	requestInfo, err := newWebContentFilteringPolicyRuleRequestInformation(ctx, adapter, abstractions.POST, policyID, "", requestBody)
	if err != nil {
		return nil, err
	}

	result, err := adapter.Send(ctx, requestInfo, createWebContentFilteringPolicyRuleResponseFromDiscriminatorValue, webContentFilteringPolicyRuleErrorMapping)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("create web content filtering policy rule returned nil response")
	}

	rule, ok := result.(*webContentFilteringPolicyRuleResponse)
	if !ok {
		return nil, fmt.Errorf("create web content filtering policy rule returned %T, expected webContentFilteringPolicyRuleResponse", result)
	}

	return rule, nil
}

func (r *NetworkWebContentFilteringPolicyRuleResource) getWebContentFilteringPolicyRule(ctx context.Context, policyID, ruleID string) (*webContentFilteringPolicyRuleResponse, error) {
	adapter := r.client.GetAdapter()
	requestInfo, err := newWebContentFilteringPolicyRuleRequestInformation(ctx, adapter, abstractions.GET, policyID, ruleID, nil)
	if err != nil {
		return nil, err
	}

	result, err := adapter.Send(ctx, requestInfo, createWebContentFilteringPolicyRuleResponseFromDiscriminatorValue, webContentFilteringPolicyRuleErrorMapping)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	rule, ok := result.(*webContentFilteringPolicyRuleResponse)
	if !ok {
		return nil, fmt.Errorf("get web content filtering policy rule returned %T, expected webContentFilteringPolicyRuleResponse", result)
	}

	return rule, nil
}

func (r *NetworkWebContentFilteringPolicyRuleResource) updateWebContentFilteringPolicyRule(ctx context.Context, policyID, ruleID string, requestBody s.Parsable) error {
	adapter := r.client.GetAdapter()
	requestInfo, err := newWebContentFilteringPolicyRuleRequestInformation(ctx, adapter, abstractions.PATCH, policyID, ruleID, requestBody)
	if err != nil {
		return err
	}

	return adapter.SendNoContent(ctx, requestInfo, webContentFilteringPolicyRuleErrorMapping)
}

func (r *NetworkWebContentFilteringPolicyRuleResource) deleteWebContentFilteringPolicyRule(ctx context.Context, policyID, ruleID string) error {
	adapter := r.client.GetAdapter()
	requestInfo, err := newWebContentFilteringPolicyRuleRequestInformation(ctx, adapter, abstractions.DELETE, policyID, ruleID, nil)
	if err != nil {
		return err
	}

	return adapter.SendNoContent(ctx, requestInfo, webContentFilteringPolicyRuleErrorMapping)
}

func newWebContentFilteringPolicyRuleRequestInformation(ctx context.Context, adapter abstractions.RequestAdapter, method abstractions.HttpMethod, policyID, ruleID string, requestBody s.Parsable) (*abstractions.RequestInformation, error) {
	pathParameters := map[string]string{
		"baseurl":                     adapter.GetBaseUrl(),
		"webContentFilteringPolicyId": policyID,
	}

	urlTemplate := webContentFilteringPolicyRulesURLTemplate
	if ruleID != "" {
		urlTemplate = webContentFilteringPolicyRuleItemURLTemplate
		pathParameters["policyRuleId"] = ruleID
	}

	requestInfo := abstractions.NewRequestInformationWithMethodAndUrlTemplateAndPathParameters(method, urlTemplate, pathParameters)
	requestInfo.Headers.TryAdd("Accept", "application/json")

	if requestBody != nil {
		if err := requestInfo.SetContentFromParsable(ctx, adapter, "application/json", requestBody); err != nil {
			return nil, fmt.Errorf("set web content filtering policy rule request content: %w", err)
		}
	}

	return requestInfo, nil
}
