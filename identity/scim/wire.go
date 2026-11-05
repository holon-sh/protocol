package scim

const (
	schemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaUserExtension         = "urn:holon:params:scim:schemas:extension:user:1.0"
	schemaCapabilities          = "urn:holon:params:scim:schemas:extension:capabilities:1.0"
	schemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
)

type userResource struct {
	User

	Schemas []string `json:"schemas"`
}

type groupResource struct {
	Group

	Schemas []string `json:"schemas"`
}

type patchOp struct {
	Patch

	Schemas []string `json:"schemas"`
}

type listResponse[T any] struct {
	Page[T]

	Schemas []string `json:"schemas"`
}

type errorResponse struct {
	Schemas  []string `json:"schemas"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   string   `json:"status"`
}

func userResponse(user User) userResource {
	schemas := []string{schemaUser}
	if user.Holon != nil {
		schemas = append(schemas, schemaUserExtension)
	}
	response := userResource{User: user, Schemas: schemas}
	response.Password = ""
	response.Meta.ResourceType = "User"
	return response
}

func groupResponse(group Group) groupResource {
	response := groupResource{Group: group, Schemas: []string{schemaGroup}}
	response.Meta.ResourceType = "Group"
	return response
}

func (p Patch) scimType() string {
	if len(p.Operations) == 0 {
		return "invalidSyntax"
	}
	for _, operation := range p.Operations {
		switch {
		case operation.Op != "add" && operation.Op != "remove" && operation.Op != "replace":
			return "invalidSyntax"
		case operation.Op == "remove" && operation.Path == "":
			return "noTarget"
		case operation.Op != "remove" && len(operation.Value) == 0:
			return "invalidValue"
		}
	}
	return ""
}

// serviceProviderConfig is [RFC 7643 §5] plus Holon's capabilities extension. Handler sets Schemas, so a
// backend leaves it empty.
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
type serviceProviderConfig struct {
	Schemas        []string     `json:"schemas"`
	Patch          supported    `json:"patch"`
	Bulk           supported    `json:"bulk"`
	Filter         filtering    `json:"filter"`
	ChangePassword supported    `json:"changePassword"`
	Sort           supported    `json:"sort"`
	ETag           supported    `json:"etag"`
	Holon          Capabilities `json:"urn:holon:params:scim:schemas:extension:capabilities:1.0"`
}

// supported is a boolean capability of [RFC 7643 §5].
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
type supported struct {
	Supported bool `json:"supported"`
}

// filtering is the filter capability of [RFC 7643 §5].
//
// [RFC 7643 §5]: https://www.rfc-editor.org/rfc/rfc7643.html#section-5
type filtering struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}
