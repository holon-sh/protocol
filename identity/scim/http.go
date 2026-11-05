package scim

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/holon-sh/protocol/identity/internal/adapter"
)

const (
	mediaType      = "application/scim+json"
	maxBody        = 64 << 10
	maxCount       = 200
	requestTimeout = 30 * time.Second
)

// Handler serves backend under /scim/v2 with the media type of [RFC 7644 §3.1], creation per [RFC 7644 §3.3],
// listing per [RFC 7644 §3.4.2] with the pagination of [RFC 7644 §3.4.2.4], PATCH per [RFC 7644 §3.5.2],
// deletion per [RFC 7644 §3.6] and errors per [RFC 7644 §3.12]. Every request carries the shared bearer.
// Read-only attributes in a request are ignored and a password is never returned, as [RFC 7643 §7] requires
// of its mutability and returned settings.
//
// [RFC 7644 §3.1]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.1
// [RFC 7644 §3.3]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3
// [RFC 7644 §3.4.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2
// [RFC 7644 §3.4.2.4]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.4
// [RFC 7644 §3.5.2]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2
// [RFC 7644 §3.6]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.6
// [RFC 7644 §3.12]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.12
// [RFC 7643 §7]: https://www.rfc-editor.org/rfc/rfc7643.html#section-7
func Handler(backend Backend, bearer string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", func(w http.ResponseWriter, r *http.Request) {
		config, err := backend.Config(r.Context())
		if err != nil {
			failWith(w, err)
			return
		}
		config.Schemas = []string{schemaServiceProviderConfig, schemaCapabilities}
		respond(w, http.StatusOK, config)
	})
	mux.HandleFunc("GET /scim/v2/Users", func(w http.ResponseWriter, r *http.Request) {
		list(w, r, backend.ListUsers, userResponse)
	})
	mux.HandleFunc("POST /scim/v2/Users", func(w http.ResponseWriter, r *http.Request) {
		createUser(w, r, backend)
	})
	mux.HandleFunc("GET /scim/v2/Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		user, err := backend.GetUser(r.Context(), r.PathValue("id"))
		if err != nil {
			failWith(w, err)
			return
		}
		respond(w, http.StatusOK, userResponse(user))
	})
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		patch(w, r, backend.PatchUser, userResponse)
	})
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := backend.DeleteUser(r.Context(), r.PathValue("id")); err != nil {
			failWith(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /scim/v2/Groups", func(w http.ResponseWriter, r *http.Request) {
		list(w, r, func(ctx context.Context, filter Filter, start, count int) (Page[Group], error) {
			if filter != (Filter{}) {
				return Page[Group]{}, ErrFilter
			}
			return backend.ListGroups(ctx, filter, start, count)
		}, groupResponse)
	})
	mux.HandleFunc("POST /scim/v2/Groups", func(w http.ResponseWriter, r *http.Request) {
		createGroup(w, r, backend)
	})
	mux.HandleFunc("PATCH /scim/v2/Groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		patch(w, r, backend.PatchGroup, groupResponse)
	})
	mux.HandleFunc("/scim/v2/", func(w http.ResponseWriter, _ *http.Request) {
		fail(w, http.StatusNotImplemented, "", "not implemented")
	})
	return adapter.Guard(bearer, "scim", requestTimeout, func(w http.ResponseWriter) {
		fail(w, http.StatusUnauthorized, "", "unauthorized")
	}, mux)
}

func createUser(w http.ResponseWriter, r *http.Request, backend Backend) {
	var request userResource
	if !read(w, r, &request, &request.Schemas, schemaUser) {
		return
	}
	if request.UserName == "" {
		fail(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	created, err := backend.CreateUser(r.Context(), User{
		ExternalID: request.ExternalID, UserName: request.UserName, Name: request.Name,
		Emails: request.Emails, Active: request.Active, Password: request.Password,
	})
	if err != nil {
		failWith(w, err)
		return
	}
	w.Header().Set("Location", "/scim/v2/Users/"+url.PathEscape(created.ID))
	respond(w, http.StatusCreated, userResponse(created))
}

func createGroup(w http.ResponseWriter, r *http.Request, backend Backend) {
	var request groupResource
	if !read(w, r, &request, &request.Schemas, schemaGroup) {
		return
	}
	created, err := backend.CreateGroup(r.Context(), Group{ExternalID: request.ExternalID})
	if err != nil {
		failWith(w, err)
		return
	}
	w.Header().Set("Location", "/scim/v2/Groups/"+url.PathEscape(created.ID))
	respond(w, http.StatusCreated, groupResponse(created))
}

func list[T, W any](w http.ResponseWriter, r *http.Request, run func(context.Context, Filter, int, int) (Page[T], error), wrap func(T) W) {
	query := r.URL.Query()
	filter, err := parseFilter(query.Get("filter"))
	if err != nil {
		failWith(w, err)
		return
	}
	start, count, err := pagination(query)
	if err != nil {
		failWith(w, err)
		return
	}
	result, err := run(r.Context(), filter, start, count)
	if err != nil {
		failWith(w, err)
		return
	}
	resources := make([]W, len(result.Resources))
	for i, resource := range result.Resources {
		resources[i] = wrap(resource)
	}
	page := Page[W]{TotalResults: result.TotalResults, StartIndex: start, ItemsPerPage: len(resources), Resources: resources}
	respond(w, http.StatusOK, listResponse[W]{Page: page, Schemas: []string{schemaListResponse}})
}

func patch[T, W any](w http.ResponseWriter, r *http.Request, run func(context.Context, string, Patch) (T, error), wrap func(T) W) {
	var request patchOp
	if !read(w, r, &request, &request.Schemas, schemaPatchOp) {
		return
	}
	if scimType := request.scimType(); scimType != "" {
		fail(w, http.StatusBadRequest, scimType, "invalid patch operation")
		return
	}
	result, err := run(r.Context(), r.PathValue("id"), request.Patch)
	if err != nil {
		failWith(w, err)
		return
	}
	respond(w, http.StatusOK, wrap(result))
}

func pagination(query url.Values) (int, int, error) {
	start, startErr := strconv.Atoi(cmp.Or(query.Get("startIndex"), "1"))
	count, countErr := strconv.Atoi(cmp.Or(query.Get("count"), strconv.Itoa(maxCount)))
	if startErr != nil || countErr != nil {
		return 0, 0, ErrInvalid
	}
	return max(start, 1), min(max(count, 0), maxCount), nil
}

func read(w http.ResponseWriter, r *http.Request, output any, schemas *[]string, schema string) bool {
	if !adapter.HasMediaType(r, mediaType) {
		fail(w, http.StatusUnsupportedMediaType, "", "content type must be "+mediaType)
		return false
	}
	if adapter.Decode(http.MaxBytesReader(w, r.Body, maxBody), output) != nil || !slices.Contains(*schemas, schema) {
		fail(w, http.StatusBadRequest, "invalidSyntax", "request body does not match "+schema)
		return false
	}
	return true
}

func failWith(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrFilter):
		fail(w, http.StatusBadRequest, "invalidFilter", "only userName, emails.value and groups.value eq are supported")
	case errors.Is(err, ErrInvalid):
		fail(w, http.StatusBadRequest, "invalidValue", "invalid value")
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, ErrConflict):
		fail(w, http.StatusConflict, "uniqueness", "resource already exists")
	default:
		fail(w, http.StatusServiceUnavailable, "", "backend unavailable")
	}
}

func fail(w http.ResponseWriter, status int, scimType, detail string) {
	respond(w, status, errorResponse{Schemas: []string{schemaError}, ScimType: scimType, Detail: detail, Status: strconv.Itoa(status)})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
