// Package rule describes the values on Holon's wire as Go data, from which the documents under spec/ are written.
package rule

// A Rule is one of the kinds below. A rule with a Name is written once under $defs and referred to wherever it is used.
type Rule interface{ name() string }

// Text is a string of at least MinBytes and, unless MaxBytes is 0, at most MaxBytes UTF-8 bytes, and unless MaxChars is
// 0 at most MaxChars characters, that matches Pattern when it is set, is none of Excluded, and holds no NUL, CR or LF
// when SingleLine is set. A schema counts characters, so it states a byte bound as that many characters.
type Text struct {
	Name       string
	Pattern    string
	MinBytes   int
	MaxBytes   int
	MaxChars   int
	Excluded   []string
	SingleLine bool
}

// Integer is a whole number within the bounds that are set.
type Integer struct {
	Name     string
	Min, Max *int64
}

// Boolean is true or false.
type Boolean struct{ Name string }

// Enumeration is one of a closed set of strings.
type Enumeration struct {
	Name   string
	Values []string
}

// List is an array of items that each follow Item, with at least MinItems and, unless MaxItems is 0, at most MaxItems
// of them. The items of a Set are distinct.
type List struct {
	Name               string
	Item               Rule
	MinItems, MaxItems int
	Set                bool
}

// Map is an object whose member names follow Key and whose values follow Value, with at most MaxEntries members unless
// it is 0.
type Map struct {
	Name       string
	Key        Text
	Value      Rule
	MaxEntries int
}

// Object is an object with exactly the members listed. Its unions constrain which of those members appear together.
type Object struct {
	Name    string
	Members []Member
	Unions  []Union
}

// A Member that is Nullable may also be null, and one whose ZeroIsAbsent is set may also be its rule's zero value: "",
// 0 or false. A reader takes either as the member's absence.
type Member struct {
	Name         string
	Rule         Rule
	Required     bool
	Nullable     bool
	ZeroIsAbsent bool
	Description  string
}

// Union names the variants of the object that holds it, since the wire spreads a union's members across that object.
// Exactly one variant applies.
type Union struct{ Variants []Variant }

// Variant applies when its Select member is present, or when no other variant's is if Select is empty. Of the members
// that the union's variants name, only Select and Members may then appear. A member that may be absent as null or as its
// zero value counts as present only when it is neither.
type Variant struct {
	Select  string
	Members []string
}

// Opaque is any JSON value.
type Opaque struct{ Name string }

func (r Text) name() string        { return r.Name }
func (r Integer) name() string     { return r.Name }
func (r Boolean) name() string     { return r.Name }
func (r Enumeration) name() string { return r.Name }
func (r List) name() string        { return r.Name }
func (r Map) name() string         { return r.Name }
func (r Object) name() string      { return r.Name }
func (r Opaque) name() string      { return r.Name }
