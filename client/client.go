package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/xerrors"

	"github.com/Yamashou/gqlgenc/graphqljson"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// HTTPRequestOption represents the options applicable to the http client
type HTTPRequestOption func(ctx context.Context, req *http.Request)
type HTTPResponseCallback func(ctx context.Context, res *http.Response)

type PersistedQuery struct {
	Version    int      `json:"version"`
	Sha256Hash [32]byte `json:"sha256Hash"`
}

type Extensions struct {
	PersistedQuery PersistedQuery `json:"persistedQuery, omitempty"`
}

// Client is the http client wrapper
type Client struct {
	ClientPool            ClientPool
	HTTPRequestOptions    []HTTPRequestOption
	HTTPResponseCallbacks []HTTPResponseCallback
}

// Request represents an outgoing GraphQL request
type Request struct {
	Query         string                 `json:"query,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	OperationName string                 `json:"operationName,omitempty"`
	Extensions    Extensions             `json:"extensions,omitempty"`
}

// NewClient creates a new http client wrapper
func NewClient(
	clientPool ClientPool,
	options []HTTPRequestOption,
	callbacks []HTTPResponseCallback,
) *Client {
	return &Client{
		ClientPool:            clientPool,
		HTTPRequestOptions:    options,
		HTTPResponseCallbacks: callbacks,
	}
}

func (c *Client) newPersistedRequest(
	ctx context.Context,
	host, endpoint string,
	operationName string,
	queryHash [32]byte,
	vars map[string]interface{},
	httpRequestOptions []HTTPRequestOption,
	httpResponseCallbacks []HTTPResponseCallback,
) (*http.Request, error) {
	r := &Request{
		Extensions: Extensions{
			PersistedQuery: PersistedQuery{
				Version:    1,
				Sha256Hash: queryHash,
			},
		},
		Variables:     vars,
		OperationName: operationName,
	}

	requestBody, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("create request struct failed: %w", err)
	}
	req.Host = host

	for _, httpRequestOption := range c.HTTPRequestOptions {
		httpRequestOption(ctx, req)
	}
	for _, httpRequestOption := range httpRequestOptions {
		httpRequestOption(ctx, req)
	}

	return req, nil
}

func (c *Client) newRequest(
	ctx context.Context,
	host, endpoint string,
	operationName, query string,
	queryHash [32]byte,
	vars map[string]interface{},
	httpRequestOptions []HTTPRequestOption,
	httpResponseCallbacks []HTTPResponseCallback,
) (*http.Request, error) {
	r := &Request{
		Query:         query,
		Variables:     vars,
		OperationName: operationName,
		Extensions: Extensions{
			PersistedQuery: PersistedQuery{
				Version:    1,
				Sha256Hash: queryHash,
			},
		},
	}

	requestBody, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("create request struct failed: %w", err)
	}
	req.Host = host

	for _, httpRequestOption := range c.HTTPRequestOptions {
		httpRequestOption(ctx, req)
	}
	for _, httpRequestOption := range httpRequestOptions {
		httpRequestOption(ctx, req)
	}

	return req, nil
}

// GqlErrorList is the struct of a standard graphql error response
type GqlErrorList struct {
	Errors gqlerror.List `json:"errors"`
}

func (e *GqlErrorList) Error() string {
	return e.Errors.Error()
}

// HTTPError is the error when a GqlErrorList cannot be parsed
type HTTPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorResponse represent an handled error
type ErrorResponse struct {
	// populated when http status code is not OK
	NetworkError *HTTPError `json:"networkErrors"`
	// populated when http status code is OK but the server returned at least one graphql error
	GqlErrors *gqlerror.List `json:"graphqlErrors"`
}

// HasErrors returns true when at least one error is declared
func (er *ErrorResponse) HasErrors() bool {
	return er.NetworkError != nil || er.GqlErrors != nil
}

func (er *ErrorResponse) Error() string {
	content, err := json.Marshal(er)
	if err != nil {
		return err.Error()
	}

	return string(content)
}

// Post sends a http POST request to the graphql endpoint with the given query then unpacks
// the response into the given object.
func (c *Client) Post(ctx context.Context, operationName, query string, respData interface{}, vars map[string]interface{}, httpRequestOptions []HTTPRequestOption,
	httpResponseCallbacks []HTTPResponseCallback) error {
	host := c.ClientPool.GetHost()
	endpoint := c.ClientPool.GetEndpoint()

	// todo[igni]: grab the hash somewhere
	sha256Hash := sha256.Sum256([]byte(query))

	for {
		httpCl, _ := c.ClientPool.GetClient()

		apqReq, err := c.newPersistedRequest(ctx,
			host, endpoint, operationName,
			sha256Hash, vars,
			httpRequestOptions, httpResponseCallbacks,
		)
		if err != nil {
			return xerrors.Errorf("don't create request: %w", err)
		}
		apqReq.Header.Set("Content-Type", "application/json; charset=utf-8")
		apqReq.Header.Set("Accept", "application/json; charset=utf-8")

		res, err := httpCl.Do(apqReq)
		if err != nil {
			if innerErr, ok := err.(*url.Error); ok {
				if !(innerErr.Err == context.DeadlineExceeded ||
					innerErr.Err == context.Canceled) {
					c.ClientPool.Refresh(fmt.Sprintf("%#v (%#v)", err, innerErr.Err))
					continue
				}
			}
			// Perform a regular request if the APQ one failed
			req, err := c.newRequest(ctx,
				host, endpoint, operationName,
				query, sha256Hash, vars,
				httpRequestOptions, httpResponseCallbacks,
			)
			if err != nil {
				return xerrors.Errorf("don't create request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
			req.Header.Set("Accept", "application/json; charset=utf-8")

			res, err = httpCl.Do(req)
		}

		if err != nil {
			if innerErr, ok := err.(*url.Error); ok {
				if !(innerErr.Err == context.DeadlineExceeded ||
					innerErr.Err == context.Canceled) {
					c.ClientPool.Refresh(fmt.Sprintf("%#v (%#v)", err, innerErr.Err))
					continue
				}
			}
			return xerrors.Errorf("request failed: %w", err)
		}
		body, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		if err := parseResponse(body, res.StatusCode, respData); err != nil {
			return fmt.Errorf("unable to parse response: %w", err)
		}

		for _, httpResponseCallback := range c.HTTPResponseCallbacks {
			httpResponseCallback(ctx, res)
		}
		for _, callback := range httpResponseCallbacks {
			callback(ctx, res)
		}

		return nil
	}
}

func parseResponse(body []byte, httpCode int, result interface{}) error {
	errResponse := &ErrorResponse{}
	isKOCode := httpCode < 200 || 299 < httpCode
	if isKOCode {
		errResponse.NetworkError = &HTTPError{
			Code:    httpCode,
			Message: fmt.Sprintf("Response body %s", string(body)),
		}
	}

	// some servers return a graphql error with a non OK http code, try anyway to parse the body
	if err := unmarshal(body, result); err != nil {
		if gqlErr, ok := err.(*GqlErrorList); ok {
			errResponse.GqlErrors = &gqlErr.Errors
		} else if !isKOCode { // if is KO code there is already the http error, this error should not be returned
			return err
		}
	}

	if errResponse.HasErrors() {
		return errResponse
	}

	return nil
}

// response is a GraphQL layer response from a handler.
type response struct {
	Data   json.RawMessage `json:"data"`
	Errors json.RawMessage `json:"errors"`
}

func unmarshal(data []byte, res interface{}) error {
	resp := response{}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to decode data %s: %w", string(data), err)
	}

	if resp.Errors != nil && len(resp.Errors) > 0 {
		// try to parse standard graphql error
		errors := &GqlErrorList{}
		if e := json.Unmarshal(data, errors); e != nil {
			return fmt.Errorf("faild to parse graphql errors. Response content %s - %w ", string(data), e)
		}

		return errors
	}

	if err := graphqljson.UnmarshalData(resp.Data, res); err != nil {
		return fmt.Errorf("failed to decode data into response %s: %w", string(data), err)
	}

	return nil
}
