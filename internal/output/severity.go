// Package output provides severity classification for pattern rules.
package output

import "strings"

// severityPrefixMap maps pattern ID prefixes to severity levels.
// This covers the 57 built-in rules from patterns/rules.toml.
var severityPrefixMap = map[string]string{
	// HIGH: Direct credentials that grant access
	"aws-":                "HIGH",
	"stripe-secret-":      "HIGH",
	"stripe-restricted-":  "HIGH",
	"stripe-webhook-":     "HIGH",
	"slack-bot-":          "HIGH",
	"slack-user-":         "HIGH",
	"slack-app-":          "HIGH",
	"twilio-":             "HIGH",
	"sendgrid-":           "HIGH",
	"mailgun-":            "HIGH",
	"mailchimp-":          "HIGH",
	"github-":             "HIGH",
	"gitlab-":             "HIGH",
	"google-api-key":      "HIGH",
	"google-oauth-":       "HIGH",
	"firebase-":           "HIGH",
	"azure-":              "HIGH",
	"datadog-":            "HIGH",
	"vault-token":         "HIGH",
	"heroku-":             "HIGH",
	"digitalocean-":       "HIGH",
	"shopify-":            "HIGH",
	"terraform-":          "HIGH",
	"jwt-token":           "HIGH",
	"private-key-":        "HIGH",
	"facebook-":           "HIGH",
	"twitter-":            "HIGH",
	"discord-":            "HIGH",
	"telegram-":           "HIGH",
	"mongo-":              "HIGH",
	"docker-hub-":         "HIGH",
	"sonarqube-":          "HIGH",
	"bitbucket-":          "HIGH",
	"pypi-":               "HIGH",
	"npm-":                "HIGH",
	"rubygems-":           "HIGH",

	// MEDIUM: Useful but less critical / public by design
	"slack-webhook-":      "MEDIUM",
	"stripe-publishable-": "MEDIUM",
	"google-pagination-":  "MEDIUM",

	// LOW: High false-positive potential, generic patterns
	"generic-":            "LOW",
	"password-in-url":     "LOW",
	"high-entropy-":       "LOW",
}

// SeverityFromPattern returns the severity level for a given pattern ID.
// Returns "MEDIUM" as default for unknown patterns.
func SeverityFromPattern(patternID string) string {
	patternID = strings.ToLower(patternID)
	for prefix, severity := range severityPrefixMap {
		if strings.HasPrefix(patternID, prefix) {
			return severity
		}
	}
	return "MEDIUM"
}