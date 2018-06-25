package web

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"net/http"
)

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// GlobalResourceGroupsClient is the webSite Management Client
type GlobalResourceGroupsClient struct {
	BaseClient
}

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// NewGlobalResourceGroupsClient creates an instance of the GlobalResourceGroupsClient client.
func NewGlobalResourceGroupsClient(subscriptionID string) GlobalResourceGroupsClient {
	return NewGlobalResourceGroupsClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// NewGlobalResourceGroupsClientWithBaseURI creates an instance of the GlobalResourceGroupsClient client.
func NewGlobalResourceGroupsClientWithBaseURI(baseURI string, subscriptionID string) GlobalResourceGroupsClient {
	return GlobalResourceGroupsClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// MoveResources sends the move resources request.
//
func (client GlobalResourceGroupsClient) MoveResources(ctx context.Context, resourceGroupName string, moveResourceEnvelope CsmMoveResourceEnvelope) (result autorest.Response, err error) {
	req, err := client.MoveResourcesPreparer(ctx, resourceGroupName, moveResourceEnvelope)
	if err != nil {
		err = autorest.NewErrorWithError(err, "web.GlobalResourceGroupsClient", "MoveResources", nil, "Failure preparing request")
		return
	}

	resp, err := client.MoveResourcesSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "web.GlobalResourceGroupsClient", "MoveResources", resp, "Failure sending request")
		return
	}

	result, err = client.MoveResourcesResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "web.GlobalResourceGroupsClient", "MoveResources", resp, "Failure responding to request")
	}

	return
}

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// MoveResourcesPreparer prepares the MoveResources request.
func (client GlobalResourceGroupsClient) MoveResourcesPreparer(ctx context.Context, resourceGroupName string, moveResourceEnvelope CsmMoveResourceEnvelope) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2015-08-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/moveResources", pathParameters),
		autorest.WithJSON(moveResourceEnvelope),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// MoveResourcesSender sends the MoveResources request. The method will close the
// http.Response Body if it receives an error.
func (client GlobalResourceGroupsClient) MoveResourcesSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req,
		azure.DoRetryWithRegistration(client.Client))
}

// Deprecated: Please use package github.com/Azure/azure-sdk-for-go/services/preview/web/mgmt/2015-08-preview/web instead.
// MoveResourcesResponder handles the response to the MoveResources request. The method always
// closes the http.Response Body.
func (client GlobalResourceGroupsClient) MoveResourcesResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByClosing())
	result.Response = resp
	return
}