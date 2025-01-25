package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// Role represents a simplified version of the IAM role
type Role struct {
	Name                string   `json:"name"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	IncludedPermissions []string `json:"included_permissions"`
	Stage               string   `json:"stage"`
}

func main() {
	// Initialize context
	ctx := context.Background()

	// Initialize IAM service with credentials
	iamService, err := iam.NewService(ctx, option.WithCredentialsFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")))
	if err != nil {
		log.Fatalf("Failed to create IAM service: %v", err)
	}

	// Call the IAM API to list roles
	roles, err := listAllRoles(ctx, iamService)
	if err != nil {
		log.Fatalf("Failed to list roles: %v", err)
	}

	// Ensure the output directory exists
	outputDir := "output"
	err = os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Iterate over each role to fetch detailed information
	for _, role := range roles {
		// Log the API call
		log.Printf("Fetching details for role: %s", role.Name)

		// Fetch role details
		detailedRole, err := getRoleDetails(ctx, iamService, role.Name)
		if err != nil {
			log.Printf("Error fetching details for role %s: %v", role.Name, err)
			continue // Skip to the next role on error
		}

		// Replace "/" with "-" in role name for filename
		filename := strings.ReplaceAll(detailedRole.Name, "/", "-") + ".json"
		filePath := fmt.Sprintf("%s/%s", outputDir, filename)

		// Marshal role details to JSON
		jsonData, err := json.MarshalIndent(detailedRole, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal role %s to JSON: %v", detailedRole.Name, err)
			continue
		}

		// Write JSON data to file
		err = os.WriteFile(filePath, jsonData, 0644)
		if err != nil {
			log.Printf("Failed to write JSON for role %s to file: %v", detailedRole.Name, err)
			continue
		}

		log.Printf("Successfully saved role %s to %s", detailedRole.Name, filePath)
	}

	fmt.Printf("Successfully processed %d roles. Check the '%s' directory for detailed JSON files.\n", len(roles), outputDir)
}

// listAllRoles retrieves all IAM roles using pagination
func listAllRoles(ctx context.Context, iamService *iam.Service) ([]Role, error) {
	var allRoles []Role
	pageToken := ""

	for {
		call := iamService.Roles.List().ShowDeleted(false)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}

		// Execute the API call
		resp, err := call.Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("error listing roles: %v", err)
		}

		// Process each role in the response
		for _, r := range resp.Roles {
			role := Role{
				Name:        r.Name,
				Title:       r.Title,
				Description: r.Description,
				Stage:       r.Stage,
			}
			allRoles = append(allRoles, role)
		}

		// Check if there are more pages
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return allRoles, nil
}

// getRoleDetails fetches detailed information for a specific role
func getRoleDetails(ctx context.Context, iamService *iam.Service, roleName string) (*Role, error) {
	// Make the API call to get role details
	r, err := iamService.Roles.Get(roleName).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("error getting role details: %v", err)
	}

	// Map the response to the Role struct
	detailedRole := &Role{
		Name:                r.Name,
		Title:               r.Title,
		Description:         r.Description,
		IncludedPermissions: r.IncludedPermissions,
		Stage:               r.Stage,
	}

	return detailedRole, nil
}
