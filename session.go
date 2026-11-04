package protocol

import (
	"encoding/json"
	"time"
)

const (
	ConditionReady         = "Ready"
	ConditionAvailable     = "Available"
	ReasonInvalidIdentity  = "InvalidIdentity"
	ReasonInvalidExpiry    = "InvalidExpiry"
	ReasonInvalidSpec      = "InvalidSpec"
	ReasonDeleting         = "Deleting"
	ReasonLeaseExpired     = "LeaseExpired"
	ReasonProgressDeadline = "ProgressDeadlineExceeded"
)

type Owner struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"sub"`
}

type LifecycleOperation struct {
	Initiator *Owner `json:"initiator,omitempty"`
	ID        string `json:"id"`
	Retry     int64  `json:"retry,omitempty"`
}

type LifecycleStatus struct {
	App       string   `json:"app,omitempty"`
	Hook      string   `json:"hook,omitempty"`
	ReadyApps []string `json:"readyApps,omitempty"`
	ID        string   `json:"id"`
	Phase     string   `json:"phase"`
	Step      int64    `json:"step"`
	Attempt   int64    `json:"attempt"`
	Retry     int64    `json:"retry,omitempty"`
	Job       string   `json:"job,omitempty"`
	JobUID    string   `json:"jobUID,omitempty"`
	Deadline  string   `json:"deadline,omitempty"`
	Message   string   `json:"message,omitempty"`
}

type InstalledRelease struct {
	Name           string `json:"name"`
	Installed      *App   `json:"installed,omitempty"`
	ServingVersion string `json:"servingVersion,omitempty"`
}

type SessionEndpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	LastTransitionTime Time   `json:"lastTransitionTime"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
}

type SessionResponse struct {
	Operation          *LifecycleOperation `json:"operation,omitempty"`
	Lifecycle          *LifecycleStatus    `json:"lifecycle,omitempty"`
	Releases           []InstalledRelease  `json:"releases,omitempty"`
	Detached           bool                `json:"detached,omitempty"`
	BuildArchitectures []string            `json:"buildArchitectures,omitempty"`
	UID                string              `json:"uid"`
	Apps               []App               `json:"apps"`
	Generation         int64               `json:"generation,omitempty"`
	Name               string              `json:"name"`
	Endpoints          []SessionEndpoint   `json:"endpoints"`
	Conditions         []Condition         `json:"conditions"`
	ExpiresAt          string              `json:"expiresAt,omitempty"`
	Revision           string              `json:"revision"`
}

type Time time.Time

func (value *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*value = Time{}
		return nil
	}
	return (*time.Time)(value).UnmarshalJSON(data)
}

func (value Time) MarshalJSON() ([]byte, error) {
	stamp := time.Time(value)
	if stamp.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(stamp.UTC().Format(time.RFC3339))
}

func (session SessionResponse) Condition(kind string) Condition {
	for _, condition := range session.Conditions {
		if condition.Type == kind {
			return condition
		}
	}
	return Condition{}
}
