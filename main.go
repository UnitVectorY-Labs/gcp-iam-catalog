package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	PermissionCount     int      `json:"-"` // Not stored in JSON
}

// PermissionIndex maps permissions to roles
type PermissionIndex map[string][]string

func main() {
	// Define command-line flags
	crawlFlag := flag.Bool("crawl", false, "Crawl GCP IAM API and save role details to JSON files")
	generateFlag := flag.Bool("generate", false, "Generate HTML files from saved JSON role details")
	flag.Parse()

	if *crawlFlag && *generateFlag {
		log.Fatal("Please specify only one command: -crawl or -generate")
	}

	if !*crawlFlag && !*generateFlag {
		flag.Usage()
		os.Exit(1)
	}

	if *crawlFlag {
		err := crawlRoles()
		if err != nil {
			log.Fatalf("Crawl failed: %v", err)
		}
	} else if *generateFlag {
		err := generateHTML()
		if err != nil {
			log.Fatalf("Generate failed: %v", err)
		}
	}
}

// crawlRoles handles the -crawl command
func crawlRoles() error {
	// Initialize context
	ctx := context.Background()

	// Initialize IAM service with credentials
	iamService, err := iam.NewService(ctx, option.WithCredentialsFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")))
	if err != nil {
		return fmt.Errorf("failed to create IAM service: %v", err)
	}

	// Call the IAM API to list roles
	roles, err := listAllRoles(ctx, iamService)
	if err != nil {
		return fmt.Errorf("failed to list roles: %v", err)
	}

	// Ensure the iam directory exists
	iamDir := "iam"
	err = os.MkdirAll(iamDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create iam directory: %v", err)
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
		filePath := filepath.Join(iamDir, filename)

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

	fmt.Printf("Crawl completed. Check the '%s' directory for detailed JSON files.\n", iamDir)
	return nil
}

// generateHTML handles the -generate command
func generateHTML() error {
	iamDir := "iam"
	htmlDir := "html"

	// Create necessary directories
	rolesHTMLDir := filepath.Join(htmlDir, "roles")
	permissionsHTMLDir := filepath.Join(htmlDir, "permissions")
	err := os.MkdirAll(rolesHTMLDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create roles HTML directory: %v", err)
	}
	err = os.MkdirAll(permissionsHTMLDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create permissions HTML directory: %v", err)
	}

	// Copy style.css to the output directory
	if err := copyFile("assets/style.css", filepath.Join(htmlDir, "style.css")); err != nil {
		log.Fatalf("Error copying style.css: %v", err)
	}

	// Read all JSON files from the iam directory
	roleFiles, err := filepath.Glob(filepath.Join(iamDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to read JSON files: %v", err)
	}

	if len(roleFiles) == 0 {
		return fmt.Errorf("no JSON files found in '%s' directory. Please run -crawl first", iamDir)
	}

	var roles []Role
	permissionIndex := make(PermissionIndex)

	// Parse all templates including footer.html
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		return fmt.Errorf("failed to parse templates: %v", err)
	}

	// Parse each role JSON file
	for _, file := range roleFiles {
		log.Printf("Processing file: %s", file)
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Failed to read file %s: %v", file, err)
			continue
		}

		var role Role
		err = json.Unmarshal(data, &role)
		if err != nil {
			log.Printf("Failed to parse JSON in file %s: %v", file, err)
			continue
		}

		// Sort IncludedPermissions alphabetically
		sort.Strings(role.IncludedPermissions)

		roles = append(roles, role)

		// Populate permission index
		for _, perm := range role.IncludedPermissions {
			permissionIndex[perm] = append(permissionIndex[perm], role.Name)
		}
	}

	// Sort roles alphabetically by Name
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Name < roles[j].Name
	})

	// Sort the roles in each permission alphabetically
	for perm, rolesWithPerm := range permissionIndex {
		sort.Strings(rolesWithPerm)
		permissionIndex[perm] = rolesWithPerm
	}

	// Generate Role Pages
	for _, role := range roles {
		filename := strings.ReplaceAll(role.Name, "roles/", "") + ".html"
		filePath := filepath.Join(rolesHTMLDir, filename)

		f, err := os.Create(filePath)
		if err != nil {
			log.Printf("Failed to create HTML file for role %s: %v", role.Name, err)
			continue
		}

		// Set the permission count
		role.PermissionCount = len(role.IncludedPermissions)

		// Execute the "role.html" template
		err = tmpl.ExecuteTemplate(f, "role.html", role)
		if err != nil {
			log.Printf("Failed to execute template for role %s: %v", role.Name, err)
			f.Close()
			continue
		}

		f.Close()
		log.Printf("Generated HTML for role %s at %s", role.Name, filePath)
	}

	// Generate Permission Pages
	for perm, rolesWithPerm := range permissionIndex {
		// Replace "/" with "-" for filename
		filename := strings.ReplaceAll(perm, "/", "-") + ".html"
		filePath := filepath.Join(permissionsHTMLDir, filename)

		data := struct {
			RoleCount  int
			Permission string
			Roles      []string
		}{
			RoleCount:  len(rolesWithPerm),
			Permission: perm,
			Roles:      rolesWithPerm,
		}

		f, err := os.Create(filePath)
		if err != nil {
			log.Printf("Failed to create HTML file for permission %s: %v", perm, err)
			continue
		}

		// Execute the "permission.html" template
		err = tmpl.ExecuteTemplate(f, "permission.html", data)
		if err != nil {
			log.Printf("Failed to execute template for permission %s: %v", perm, err)
			f.Close()
			continue
		}

		f.Close()
		log.Printf("Generated HTML for permission %s at %s", perm, filePath)
	}

	// Generate Roles Index Page
	rolesIndexPath := filepath.Join(htmlDir, "roles.html")
	fRolesIndex, err := os.Create(rolesIndexPath)
	if err != nil {
		return fmt.Errorf("failed to create roles index HTML file: %v", err)
	}
	defer fRolesIndex.Close()

	err = tmpl.ExecuteTemplate(fRolesIndex, "roles.html", struct {
		Items []Role
	}{
		Items: roles,
	})
	if err != nil {
		return fmt.Errorf("failed to execute roles index template: %v", err)
	}
	log.Printf("Generated Roles Index at %s", rolesIndexPath)

	// Generate Permissions Index Page
	var permissionsList []struct {
		Permission string
	}
	for perm := range permissionIndex {
		permissionsList = append(permissionsList, struct {
			Permission string
		}{Permission: perm})
	}

	// Sort permissionsList alphabetically by Permission
	sort.Slice(permissionsList, func(i, j int) bool {
		return permissionsList[i].Permission < permissionsList[j].Permission
	})

	permissionsIndexPath := filepath.Join(htmlDir, "permissions.html")
	fPermissionsIndex, err := os.Create(permissionsIndexPath)
	if err != nil {
		return fmt.Errorf("failed to create permissions index HTML file: %v", err)
	}
	defer fPermissionsIndex.Close()

	err = tmpl.ExecuteTemplate(fPermissionsIndex, "permissions.html", struct {
		Items []struct {
			Permission string
		}
	}{
		Items: permissionsList,
	})
	if err != nil {
		return fmt.Errorf("failed to execute permissions index template: %v", err)
	}
	log.Printf("Generated Permissions Index at %s", permissionsIndexPath)

	// Generate Home Index Page
	homeIndexPath := filepath.Join(htmlDir, "index.html")
	fHomeIndex, err := os.Create(homeIndexPath)
	if err != nil {
		return fmt.Errorf("failed to create home index HTML file: %v", err)
	}
	defer fHomeIndex.Close()

	homeData := struct {
		RoleCount       int
		PermissionCount int
	}{
		RoleCount:       len(roles),
		PermissionCount: len(permissionIndex),
	}

	// Execute the "index.html" template
	err = tmpl.ExecuteTemplate(fHomeIndex, "index.html", homeData)
	if err != nil {
		return fmt.Errorf("failed to execute home template: %v", err)
	}
	log.Printf("Generated Home Index at %s", homeIndexPath)

	fmt.Printf("HTML generation completed. Check the '%s' directory for generated HTML files.\n", htmlDir)
	return nil
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

// copyFile copies a file from source to destination.
func copyFile(source, destination string) error {
	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	return err
}
