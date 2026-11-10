package protocol

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// +kubebuilder:validation:MaxLength=4096
// +kubebuilder:validation:Pattern="^[^\\x00\\r\\n]*$"
type Template = string

// +kubebuilder:validation:MaxLength=128
type InputName = string

// +kubebuilder:validation:Pattern="^v-[0-9a-f]{24}$"
type ConfigRevision = string

// +kubebuilder:validation:XValidation:rule="has(self.remote) ? (!has(self.image) && !has(self.port)) : (has(self.image) && has(self.port))",message="apps require either a remote endpoint or an image and port"
type App struct {
	// +optional
	Icons []Icon `json:"icons,omitempty"`

	// +kubebuilder:validation:MaxLength=2048
	// +optional
	Mount string `json:"mount,omitempty"`

	// +optional
	Release *Release `json:"release,omitempty"`
	// +optional
	OAuth *OAuthClient `json:"oauth,omitempty"`
	// +optional
	Remote *Remote    `json:"remote,omitempty"`
	Access *AppAccess `json:"access"           nullable:"false" required:"true"`
	// +kubebuilder:validation:MaxLength=49
	// +kubebuilder:validation:Pattern="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
	Name string `json:"name" maxLength:"49" pattern:"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" required:"true"`
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern="@sha256:[0-9a-f]{64}$"
	// +optional
	Image string `json:"image,omitempty" pattern:"@sha256:[0-9a-f]{64}$"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty" maximum:"65535" minimum:"1"`
	// Args replace the image's command arguments. Each entry is one argument, a template over the app's inputs: the
	// container receives an entry only when every input it names has a value.
	// +kubebuilder:validation:MaxItems=64
	// +optional
	Args []Template `json:"args,omitempty" maxItems:"64"`
	// +listType=set
	// +kubebuilder:validation:items:MaxLength=49
	// +kubebuilder:validation:items:Pattern="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
	// +optional
	Requires []string `json:"requires,omitempty"`
	// +optional
	Egress Egress `json:"egress,omitzero"`
	// +kubebuilder:validation:MaxProperties=64
	// +kubebuilder:validation:XValidation:rule="!('HOLON_MCP_RUNTIME_CONFIG' in self) && !('HOLON_HOOK_CONFIG' in self)",message="Holon runtime configuration is reserved for the controller"
	// +optional
	Env map[string]Input `json:"env,omitempty"`
	// EnvTemplates sets environment variables from templates over the app's inputs. A variable is set only when every
	// input its template names has a value.
	// +kubebuilder:validation:MaxProperties=64
	// +optional
	EnvTemplates map[string]Template `json:"envTemplates,omitempty"`
	// +kubebuilder:validation:MaxProperties=64
	// +optional
	Applied map[string]ConfigRevision `json:"applied,omitempty"`
	// Supplied are the values set for the app that it does not declare. The platform adds them at deploy, so the app's
	// container receives every value set for it.
	// +kubebuilder:validation:MaxProperties=64
	// +optional
	Supplied map[string]Input `json:"supplied,omitempty"`
	// Overlay is the digest of a development app's server source, a blob in the app's upload repository.
	// +kubebuilder:validation:Pattern="^sha256:[0-9a-f]{64}$"
	// +optional
	Overlay string `json:"overlay,omitempty" pattern:"^sha256:[0-9a-f]{64}$"`
}

// +kubebuilder:validation:XValidation:rule="!(has(self.value) && has(self.default))",message="input cannot declare both value and default"
// +kubebuilder:validation:XValidation:rule="!has(self.isSecret) || !self.isSecret || (!has(self.value) && !has(self.default))",message="secret inputs must use the secret store"
// +mapType=atomic
type Input struct {
	// +nullable
	// +optional
	IsRequired bool `json:"isRequired,omitempty"`
	// +nullable
	// +optional
	IsSecret bool `json:"isSecret,omitempty"`
	// +nullable
	// +kubebuilder:validation:Pattern="^[^\\x00\\r\\n]*$"
	// +optional
	Value *string `json:"value,omitempty"`
	// +nullable
	// +kubebuilder:validation:Pattern="^[^\\x00\\r\\n]*$"
	// +optional
	Default *string `json:"default,omitempty"`
}

// +mapType=atomic
type AccessRule struct {
	// +nullable
	// +optional
	OAuth *OAuthRequirement `json:"oauth,omitempty"`
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=49
	// +kubebuilder:validation:items:Pattern="^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
	// +optional
	Callers []string `description:"App callers: omit for all; [] denies all." json:"callers,omitzero" maxItems:"256" nullable:"false" uniqueItems:"true"`
}

type OAuthRequirement struct {
	// +listType=set
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=256
	// +kubebuilder:validation:items:Pattern="^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$"
	// +optional
	Scopes []string `description:"OAuth scope tokens, at most 256 bytes." items.maxLength:"256" items.minLength:"1" json:"scopes,omitempty" uniqueItems:"true"`
}

type AppAccess struct {
	Server *AccessRule `description:"{} is public to all callers; oauth: {} requires authentication; callers: [...] admits only those apps." json:"server" nullable:"false" required:"true"`
	// +nullable
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	Tools map[string]AccessRule `description:"Tool rules replace the server rule." json:"tools,omitempty" maxProperties:"256"`
}

// +mapType=atomic
type OAuthClient struct {
	// ClientID is a template whose placeholders each name a required config input. Env may declare that input only as
	// a non-secret one without a value or default, and a placeholder never names the ClientSecret key.
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:Pattern="^[^\\x00\\r\\n]+$"
	ClientID string `json:"clientID" required:"true"`
	// +kubebuilder:validation:Pattern="^[A-Za-z_][A-Za-z0-9_]*$"
	// +optional
	ClientSecret InputName `json:"clientSecret,omitempty"`
}

// +mapType=atomic
type Remote struct {
	// URL is a template over the app's inputs.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="self.startsWith('https://')",message="remote endpoints must use HTTPS"
	URL string `json:"url" required:"true"`
	// Headers maps each header name to a template over the app's inputs. A header is sent only when every input its
	// template names has a value.
	// +kubebuilder:validation:MaxProperties=64
	// +optional
	Headers map[string]Template `json:"headers,omitempty"`
}

type EgressDestination struct {
	Host Template `description:"Exact DNS hostname or unicast IP address; {NAME} stands for a non-secret input." json:"host" required:"true"`
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	Ports []int32 `description:"Nonempty list of TCP ports from 1 to 65535." items.maximum:"65535" items.minimum:"1" json:"ports" minItems:"1" required:"true"`
}

// +listType=atomic
type Egress []EgressDestination

type Hook struct {
	Event    string `json:"event"`
	Version  string `json:"version,omitempty"`
	Path     string `json:"path"`
	Runtime  string `json:"runtime"`
	Checksum string `json:"checksum"`
}

func (h Hook) Key() string {
	if h.Version == "" {
		return h.Event
	}
	return h.Version + "/" + h.Event
}

type Artifact struct {
	Architecture string `json:"architecture"`
	WorkingDir   string `json:"workingDir"`
	Hooks        []Hook `json:"hooks,omitempty"`
}

type Release struct {
	Name      string     `json:"name,omitempty"`
	Version   string     `json:"version,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

func (i *Input) UnmarshalJSON(data []byte) error {
	type plain Input
	if err := DecodeJSONNonNull(data, (*plain)(i)); err != nil {
		return err
	}
	return i.Validate()
}

func (i Input) Validate() error {
	value := cmp.Or(i.Value, i.Default)
	if i.Value != nil && i.Default != nil {
		return errors.New("input cannot declare both value and default")
	}
	if i.IsSecret && value != nil {
		return errors.New("secret inputs must use the secret store, without literal values or defaults")
	}
	if value != nil && !ValidInputValue(*value) {
		return errors.New("input values must be single-line text without NUL characters")
	}
	return nil
}

func ValidInputValue(value string) bool {
	return !strings.ContainsAny(value, "\x00\r\n")
}

func (app *App) UnmarshalJSON(data []byte) error {
	type plainApp App
	if err := DecodeJSONStrict(data, (*plainApp)(app)); err != nil {
		var named struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(data, &named)
		return fmt.Errorf("app %s: %w", named.Name, err)
	}
	return nil
}

func (access *AppAccess) UnmarshalJSON(data []byte) error {
	type plainAccess AppAccess
	return DecodeJSONNonNull(data, (*plainAccess)(access))
}
