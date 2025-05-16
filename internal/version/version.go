package version

// These variables will be set at build time using -ldflags
var (
	// Version is the current version of the application
	Version = "dev"
	
	// Commit is the git commit hash used to build the application
	Commit = "none"
	
	// Date is the build date of the application
	Date = "unknown"
	
	// BuiltBy is the user/system that built the application
	BuiltBy = "unknown"
)

// Info returns formatted version information
func Info() string {
	return "DevDomains\n" +
		"Version:    " + Version + "\n" +
		"Commit:     " + Commit + "\n" +
		"Built:      " + Date + "\n" +
		"Built by:   " + BuiltBy + "\n"
}

// ShortInfo returns basic version information
func ShortInfo() string {
	return "DevDomains version " + Version + " (" + Commit + ")"
}