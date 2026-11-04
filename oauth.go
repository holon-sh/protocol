package protocol

import (
	"errors"
	"slices"
)

func (c *OAuthClient) Validate(env map[string]Input) error {
	if c == nil {
		return nil
	}
	if c.ClientID == "" || len(c.ClientID) > 1024 || !ValidInputValue(c.ClientID) ||
		slices.Contains(TemplateInputs(c.ClientID), c.ClientSecret) {
		return errors.New("oauth requires a client ID template and an optional secret reference")
	}
	for name, input := range c.Inputs() {
		if !ValidEnvName(name) {
			return errors.New("oauth input references must be valid environment variable names")
		}
		if declared, exists := env[name]; exists && (declared.Kind() != input.Kind() || declared.Value != nil || declared.Default != nil) {
			return errors.New("OAuth input conflicts with environment configuration")
		}
	}
	return nil
}

func (c *OAuthClient) Inputs() map[string]Input {
	inputs := map[string]Input{}
	if c != nil {
		for _, name := range TemplateInputs(c.ClientID) {
			inputs[name] = Input{IsRequired: true}
		}
		if c.ClientSecret != "" {
			inputs[c.ClientSecret] = Input{IsRequired: true, IsSecret: true}
		}
	}
	return inputs
}

func (a App) Inputs() map[string]Input {
	inputs := a.OAuth.Inputs()
	for _, destination := range a.Egress {
		for _, name := range TemplateInputs(destination.Host) {
			input := inputs[name]
			input.IsRequired = true
			inputs[name] = input
		}
	}
	for name, input := range a.Env {
		input.IsRequired = input.IsRequired || inputs[name].IsRequired
		inputs[name] = input
	}
	return inputs
}
