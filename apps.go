package protocol

const ToolResolveAppBuild = "resolve_app_build"

type AppBuildRef struct {
	Repository     string `json:"repository"     maxLength:"256"                 required:"true"`
	ArtifactDigest string `json:"artifactDigest" pattern:"^sha256:[0-9a-f]{64}$" required:"true"`
}

type ResolvedAppBuild struct {
	AppBuildRef
	BuildRecord

	Image string `json:"image,omitempty"`
}
