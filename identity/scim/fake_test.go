package scim

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"sync"
)

var _ Backend = (*Client)(nil)

type fakeBackend struct {
	mu         sync.Mutex
	next       int
	users      map[string]User
	groups     map[string]Group
	config     ServiceProviderConfig
	created    User
	start      int
	count      int
	filter     Filter
	operations []Operation
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		users: map[string]User{},
		groups: map[string]Group{
			"g1": {ID: "g1", ExternalID: "Session/one", DisplayName: "Session one"},
			"g2": {ID: "g2", ExternalID: "Session/two", DisplayName: "Session two"},
		},
	}
}

func (b *fakeBackend) Config(context.Context) (ServiceProviderConfig, error) {
	return b.config, nil
}

func window[T any](byID map[string]T, id func(T) string, start, count int) Page[T] {
	items := make([]T, 0, len(byID))
	for _, item := range byID {
		items = append(items, item)
	}
	slices.SortFunc(items, func(a, c T) int { return cmp.Compare(id(a), id(c)) })
	from := min(start-1, len(items))
	return Page[T]{TotalResults: len(items), Resources: items[from:min(from+count, len(items))]}
}

func (b *fakeBackend) ListUsers(_ context.Context, filter Filter, start, count int) (Page[User], error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.filter, b.start, b.count = filter, start, count
	return window(b.users, func(u User) string { return u.ID }, start, count), nil
}

func (b *fakeBackend) ListGroups(_ context.Context, filter Filter, start, count int) (Page[Group], error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.filter, b.start, b.count = filter, start, count
	return window(b.groups, func(g Group) string { return g.ID }, start, count), nil
}

func (b *fakeBackend) GetUser(_ context.Context, id string) (User, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	user, ok := b.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return user, nil
}

func (b *fakeBackend) CreateUser(_ context.Context, user User) (User, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.created = user
	for _, existing := range b.users {
		if existing.UserName == user.UserName {
			return User{}, ErrConflict
		}
	}
	b.next++
	created := user
	created.ID = "u" + strconv.Itoa(b.next)
	created.Holon = &UserExtension{PendingSetup: user.Password != ""}
	b.users[created.ID] = created
	return created, nil
}

func (b *fakeBackend) PatchUser(_ context.Context, id string, patch Patch) (User, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.operations = patch.Operations
	return b.users[id], nil
}

func (b *fakeBackend) DeleteUser(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.users[id]; !ok {
		return ErrNotFound
	}
	delete(b.users, id)
	return nil
}

func (b *fakeBackend) PatchGroup(_ context.Context, id string, patch Patch) (Group, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.operations = patch.Operations
	return b.groups[id], nil
}

type failingBackend struct{ err error }

func (b failingBackend) Config(context.Context) (ServiceProviderConfig, error) {
	return ServiceProviderConfig{}, b.err
}

func (b failingBackend) ListUsers(context.Context, Filter, int, int) (Page[User], error) {
	return Page[User]{}, b.err
}

func (b failingBackend) GetUser(context.Context, string) (User, error) { return User{}, b.err }

func (b failingBackend) CreateUser(context.Context, User) (User, error) { return User{}, b.err }

func (b failingBackend) DeleteUser(context.Context, string) error { return b.err }

func (b failingBackend) PatchUser(context.Context, string, Patch) (User, error) {
	return User{}, b.err
}

func (b failingBackend) ListGroups(context.Context, Filter, int, int) (Page[Group], error) {
	return Page[Group]{}, b.err
}

func (b failingBackend) PatchGroup(context.Context, string, Patch) (Group, error) {
	return Group{}, b.err
}
