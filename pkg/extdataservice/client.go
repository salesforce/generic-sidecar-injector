package extdataservice

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	v1 "k8s.io/api/admission/v1"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	Endpoint = "/"
)

type ExtDataClient struct {
	client *http.Client
	url    *url.URL
}

func NewClient(apiUrl string, tlsConfig *tls.Config) (*ExtDataClient, error) {
	parsedApiUrl, err := url.Parse(apiUrl)
	if err != nil {
		return nil, err
	}
	// Code path won't execute for localhost/sidecar call
	if needsTLS(parsedApiUrl) && tlsConfig != nil {
		return &ExtDataClient{client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				TLSNextProto:    nil,
			}}, url: parsedApiUrl}, nil
	}
	return &ExtDataClient{client: &http.Client{}, url: parsedApiUrl}, nil
}

type ExtDataResponse struct {
	Annotations map[string]string
}

type ExtDataRequest struct {
	AdmissionReview v1.AdmissionReview
}

func (c *ExtDataClient) FetchExtData(request *ExtDataRequest) (*ExtDataResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("error encoding request payload: %v", err)
	}
	req, err := http.NewRequest("GET", c.url.String()+Endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err.Error())
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error failed with status code %v", resp.StatusCode)
	}
	var extAnnotationResponse ExtDataResponse
	err = json.NewDecoder(resp.Body).Decode(&extAnnotationResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}
	return &extAnnotationResponse, nil
}

func needsTLS(apiUrl *url.URL) bool {
	if !isLocalhost(apiUrl) {
		return true
	}
	return false
}

func isLocalhost(u *url.URL) bool {
	// Split the Host into host and port
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		// If SplitHostPort fails, it might not have a port
		host = u.Host
	}

	// Convert host to lowercase for case-insensitive comparison
	host = strings.ToLower(host)

	// Check if it's localhost or an IP loopback address
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
