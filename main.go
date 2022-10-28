package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/square/go-jose.v2"

	// Load all auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const caCertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
const defauktTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type openidConfiguration struct {
	Issuer                        string   `json:"issuer"`
	JwksURI                       string   `json:"jwks_uri"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	SubjectTypesSupported         []string `json:"subject_types_supported"`
	IdTokenSigningValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func main() {
	var tokenFlag = flag.String("token", defauktTokenPath, "token path")
	flag.Parse()
	token, err := os.ReadFile(*tokenFlag)
	if err != nil {
		log.Fatalf("Error opening token: %s", err)
	}

	/*
		jwks := getJWKS(token)

		isValid, _ := validateToken(token, jwks)
		if !isValid {
			log.Fatalf("Token not valid, exitting")
		}
	*/

	tokenReview(token)
}

func getJWKS(token []byte) []byte {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("Error opening caCert: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	client := http.Client{Transport: t, Timeout: 15 * time.Second}

	// Preflight check
	log.Print("Checking APIserver connectivity")
	req, _ := http.NewRequest("GET", "https://kubernetes.default.svc/api", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to do HTTP request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("APIserver returned unexpected status code: %d", resp.StatusCode)
	}

	// Retrieving JWKs location
	log.Print("Retrieving JWKs location")
	req, _ = http.NewRequest("GET", "https://kubernetes.default.svc/.well-known/openid-configuration", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalf("Failed to do HTTP request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("APIserver returned unexpected status code: %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading body content: %s", err)
	}
	config := &openidConfiguration{}
	err = json.Unmarshal(payload, config)
	if err != nil {
		log.Fatalf("Error unmarshalling payload: %s", err)
	}

	log.Printf("OpenID configuration retreived: %#v", config)

	// Get JWKs
	log.Print("Retrieving JWKs")
	req, _ = http.NewRequest("GET", config.JwksURI, nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalf("Failed to do HTTP request: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("APIserver returned unexpected status code: %d", resp.StatusCode)
	}
	payload, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading body content: %s", err)
	}

	log.Printf("JWKs: %s", payload)
	return payload
}

func validateToken(token, rawJWKS []byte) (bool, []byte) {
	keySet := &jose.JSONWebKeySet{}
	err := json.Unmarshal(rawJWKS, keySet)
	if err != nil {
		log.Fatalf("Failed unmarshalling JSONWebKeySet: %s", err)
	}

	signature, err := jose.ParseSigned(string(token))
	if err != nil {
		log.Fatalf("failed parsing the token signature")
	}
	isValid := false
	var payload []byte
	for _, key := range keySet.Keys {
		payload, err = signature.Verify(key)
		if err != nil {
			log.Printf("Failed to validate token with key %s: %s", key.KeyID, err)
			continue
		}
		isValid = true
		break
	}

	return isValid, payload
}

func tokenReview(token []byte) {
	ctx := context.Background()
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)

	review := &v1.TokenReview{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec: v1.TokenReviewSpec{
			Token:     string(token),
			Audiences: nil,
		},
		Status: v1.TokenReviewStatus{},
	}
	options := metav1.CreateOptions{
		TypeMeta:        metav1.TypeMeta{},
		DryRun:          nil,
		FieldManager:    "",
		FieldValidation: "",
	}

	reviewResult, err := clientset.AuthenticationV1().TokenReviews().Create(ctx, review, options)
	if err != nil {
		log.Fatalf("TokenReview failed: %s")
	}

	if !reviewResult.Status.Authenticated {
		log.Fatalf("Not authenticated")
	}
	log.Print("Token valid and user authenticated")
	log.Printf("User: %s", reviewResult.Status.User.Username)
	log.Printf("Groups: %s", reviewResult.Status.User.Groups)

	if podName, ok := reviewResult.Status.User.Extra["authentication.kubernetes.io/pod-name"]; ok {
		log.Printf("Pod: %s", podName)
	}
}
