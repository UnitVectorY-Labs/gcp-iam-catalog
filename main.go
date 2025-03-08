package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dustin/go-humanize"
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

// SitemapURL represents a single URL entry in sitemap.xml
type SitemapURL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod,omitempty"`
	ChangeFreq string `xml:"changefreq,omitempty"`
	Priority   string `xml:"priority,omitempty"`
}

// Sitemap represents the sitemap.xml structure
type Sitemap struct {
	XMLName xml.Name     `xml:"urlset"`
	Xmlns   string       `xml:"xmlns,attr"`
	URLs    []SitemapURL `xml:"url"`
}

// RobotsTxt represents the robots.txt content
type RobotsTxt struct {
	SitemapURL string
	Disallow   []string
}

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

	// Create template with functions first
	tmpl := template.New("base").Funcs(template.FuncMap{
		"contains": func(s string, substrs ...string) bool {
			sLower := strings.ToLower(s)
			for _, sub := range substrs {
				if strings.Contains(sLower, strings.ToLower(sub)) {
					return true
				}
			}
			return false
		},
		"formatNumber": func(n int) string {
			return humanize.Comma(int64(n))
		},
	})

	// Then parse all templates
	tmpl, err = tmpl.ParseGlob("templates/*.html")
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

	// Copy role JSON files for client-side usage in the compare-roles page
	rolesDataDir := filepath.Join(htmlDir, "rolesdata")
	err = os.MkdirAll(rolesDataDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create roles data directory: %v", err)
	}
	for _, file := range roleFiles {
		baseName := filepath.Base(file) // e.g., "roles-compute.admin.json"
		destPath := filepath.Join(rolesDataDir, baseName)
		if err := copyFile(file, destPath); err != nil {
			log.Printf("Failed to copy %s to %s: %v", file, destPath, err)
		}
	}

	// NEW: Generate permission-based JSON for the compare-permissions page
	permissionsDataDir := filepath.Join(htmlDir, "permissionsdata")
	err = os.MkdirAll(permissionsDataDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create permissions data directory: %v", err)
	}
	type PermissionData struct {
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
	}
	for perm, rolesWithPerm := range permissionIndex {
		filename := strings.ReplaceAll(perm, "/", "-") + ".json"
		outPath := filepath.Join(permissionsDataDir, filename)
		pData := PermissionData{
			Name:  perm,
			Roles: rolesWithPerm,
		}
		jsonBytes, err := json.MarshalIndent(pData, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal permission data for %s: %v", perm, err)
			continue
		}
		if err := os.WriteFile(outPath, jsonBytes, 0644); err != nil {
			log.Printf("Failed to write permission data for %s: %v", perm, err)
		}
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

		// Populate Roles with Name and Title
		var detailedRoles []struct {
			Name  string
			Title string
		}
		for _, roleName := range rolesWithPerm {
			for _, role := range roles {
				if role.Name == roleName {
					detailedRoles = append(detailedRoles, struct {
						Name  string
						Title string
					}{
						Name:  role.Name,
						Title: role.Title,
					})
					break
				}
			}
		}

		data := struct {
			RoleCount  int
			Permission string
			Roles      []struct {
				Name  string
				Title string
			}
		}{
			RoleCount:  len(detailedRoles),
			Permission: perm,
			Roles:      detailedRoles,
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

	// Generate Compare Roles Page
	type rolesWrapper struct {
		Roles []Role
	}
	compareRolesPath := filepath.Join(htmlDir, "compare-roles.html")
	fCompareRoles, err := os.Create(compareRolesPath)
	if err != nil {
		return fmt.Errorf("failed to create compare-roles.html file: %v", err)
	}
	defer fCompareRoles.Close()

	err = tmpl.ExecuteTemplate(fCompareRoles, "compare-roles.html", rolesWrapper{Roles: roles})
	if err != nil {
		return fmt.Errorf("failed to execute compare-roles template: %v", err)
	}
	log.Printf("Generated Compare Roles page at %s", compareRolesPath)

	// NEW: Generate Compare Permissions Page (using a sorted list of all permissions)
	var allPermissions []string
	for p := range permissionIndex {
		allPermissions = append(allPermissions, p)
	}
	sort.Strings(allPermissions)
	type permissionsWrapper struct {
		Permissions []string
	}
	comparePermsPath := filepath.Join(htmlDir, "compare-permissions.html")
	fComparePerms, err := os.Create(comparePermsPath)
	if err != nil {
		return fmt.Errorf("failed to create compare-permissions.html file: %v", err)
	}
	defer fComparePerms.Close()

	err = tmpl.ExecuteTemplate(fComparePerms, "compare-permissions.html", permissionsWrapper{Permissions: allPermissions})
	if err != nil {
		return fmt.Errorf("failed to execute compare-permissions template: %v", err)
	}
	log.Printf("Generated Compare Permissions page at %s", comparePermsPath)

	// Generate sitemap.xml
	if err := generateSitemap(htmlDir); err != nil {
		log.Fatalf("Error generating sitemap.xml: %v", err)
	}

	// Generate robots.txt
	if err := generateRobotsTxt(htmlDir); err != nil {
		log.Fatalf("Error generating robots.txt: %v", err)
	}

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

// generateSitemap creates sitemap.xml based on the generated HTML files
func generateSitemap(htmlDir string) error {
	// Retrieve the WEBSITE environment variable
	website := os.Getenv("WEBSITE")
	if website == "" {
		return fmt.Errorf("environment variable 'WEBSITE' is not set")
	}

	// Ensure the website URL does not have a trailing slash
	website = strings.TrimRight(website, "/")

	var sitemap Sitemap
	sitemap.Xmlns = "http://www.sitemaps.org/schemas/sitemap/0.9"

	// Collect all .html files in htmlDir excluding any subdirectories you want to exclude
	err := filepath.Walk(htmlDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Include only .html files
		if filepath.Ext(info.Name()) == ".html" {
			relPath, err := filepath.Rel(htmlDir, path)
			if err != nil {
				return err
			}

			// Construct the URL
			urlPath := filepath.ToSlash(relPath) // Ensure URL uses forward slashes
			if urlPath == "index.html" {
				urlPath = ""
			}
			loc := fmt.Sprintf("%s/%s", website, urlPath)

			// Set LastMod to file modification time in YYYY-MM-DD format
			lastMod := info.ModTime().Format("2006-01-02")

			// Create SitemapURL entry
			sitemapURL := SitemapURL{
				Loc:     loc,
				LastMod: lastMod,
			}

			// Special case for home page
			if relPath == "index.html" {
				sitemapURL.Loc = website + "/"
			}

			sitemap.URLs = append(sitemap.URLs, sitemapURL)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking the path %q: %v", htmlDir, err)
	}

	// Sort URLs alphabetically
	sort.Slice(sitemap.URLs, func(i, j int) bool {
		return sitemap.URLs[i].Loc < sitemap.URLs[j].Loc
	})

	// Create sitemap.xml file
	sitemapFile := filepath.Join(htmlDir, "sitemap.xml")
	sitemapOut, err := os.Create(sitemapFile)
	if err != nil {
		return fmt.Errorf("failed to create sitemap.xml: %v", err)
	}
	defer sitemapOut.Close()

	// Marshal sitemap to XML with indentation
	xmlData, err := xml.MarshalIndent(sitemap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sitemap XML: %v", err)
	}

	// Add XML header
	finalSitemap := []byte(xml.Header + string(xmlData))
	if _, err := sitemapOut.Write(finalSitemap); err != nil {
		return fmt.Errorf("failed to write sitemap.xml: %v", err)
	}

	log.Println("sitemap.xml generated successfully.")
	return nil
}

// generateRobotsTxt creates robots.txt based on the generated sitemap.xml
func generateRobotsTxt(htmlDir string) error {
	// Retrieve the WEBSITE environment variable
	website := os.Getenv("WEBSITE")
	if website == "" {
		return fmt.Errorf("environment variable 'WEBSITE' is not set")
	}

	// Ensure the website URL does not have a trailing slash
	website = strings.TrimRight(website, "/")

	robots := RobotsTxt{
		SitemapURL: fmt.Sprintf("%s/sitemap.xml", website),
		Disallow:   []string{"/snippets/"},
	}

	// Parse robots.txt template from file
	tmpl, err := template.ParseFiles("templates/robots.txt")
	if err != nil {
		return fmt.Errorf("failed to parse robots.txt template: %v", err)
	}

	// Create robots.txt file
	robotsFile := filepath.Join(htmlDir, "robots.txt")
	robotsOut, err := os.Create(robotsFile)
	if err != nil {
		return fmt.Errorf("failed to create robots.txt: %v", err)
	}
	defer robotsOut.Close()

	// Execute template
	if err := tmpl.Execute(robotsOut, robots); err != nil {
		return fmt.Errorf("failed to execute robots.txt template: %v", err)
	}

	log.Println("robots.txt generated successfully.")
	return nil
}
