package protocol

const ToolResolveAppBuild = "resolve_app_build"

type AppBuildRef struct {
	Repository     string `json:"repository"`
	ArtifactDigest string `json:"artifactDigest"`
}

type ResolvedAppBuild struct {
	AppBuildRef
	BuildRecord

	Image string `json:"image,omitempty"`
}
