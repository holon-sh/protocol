package protocol

const (
	ToolImportRegistryPackage = "import_registry_package"
	ToolGetImport             = "get_import"
)

type RegistrySource struct {
	RegistryRef

	Package *PackageSelection `json:"package,omitempty"`
	Remote  *struct{}         `json:"remote,omitempty"`
}

type PackageSelection struct {
	RegistryType string `description:"MCP package registry type." enum:"oci,npm,pypi" json:"registryType" required:"true"`
	Identifier   string `json:"identifier,omitempty"`
}

type ImportRegistryPackageRequest struct {
	App      string         `json:"app"      required:"true"`
	Registry RegistrySource `json:"registry" required:"true"`
}

type GetImportRequest struct {
	ID string `json:"id" required:"true"`
}

type Import struct {
	ID      string       `json:"id"`
	Phase   string       `json:"phase"`
	Message string       `json:"message,omitempty"`
	Build   *AppBuildRef `json:"build,omitempty"`
}
