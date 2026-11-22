package protocol

const (
	ToolImportRegistryPackage = "import_registry_package"
	ToolImportRepository      = "import_repository"
	ToolGetImport             = "get_import"
)

type RegistrySource struct {
	RegistryRef

	Package *PackageSelection `json:"package,omitempty"`
}

type PackageSelection struct {
	RegistryType string `description:"MCP package registry type." enum:"oci,npm,pypi" json:"registryType" required:"true"`
	Identifier   string `json:"identifier,omitempty"`
}

type ImportRegistryPackageRequest struct {
	App      string         `json:"app"`
	Registry RegistrySource `json:"registry"`
}

type ImportRepositoryRequest struct {
	SessionRequest

	TTLSeconds int64  `json:"ttlSeconds"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Token      string `json:"token,omitempty"`
}

type GetImportRequest struct {
	ID string `json:"id"`
}

type Import struct {
	ID      string       `json:"id"`
	Phase   string       `json:"phase"`
	Message string       `json:"message,omitempty"`
	Build   *AppBuildRef `json:"build,omitempty"`
}
