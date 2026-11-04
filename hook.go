package protocol

type HookInvocation struct {
	Operation string `json:"operation"`
	Job       string `json:"job"`
	JobUID    string `json:"jobUID"`
	App       string `json:"app"`
	Step      int64  `json:"step"`
	Attempt   int64  `json:"attempt"`
	Deadline  string `json:"deadline"`
	Initiator *Owner `json:"initiator,omitempty"`
}
