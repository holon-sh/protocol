package protocol_test

import (
	"testing"

	"github.com/holon-sh/protocol"
)

func TestWebhookPathIsReservedForThePlatform(t *testing.T) {
	path := protocol.WebhookPath("github", "push")
	if path != "/webhooks/github/push" {
		t.Errorf("webhook path = %q", path)
	}
	if _, browser := protocol.BrowserPath(path); browser {
		t.Errorf("%s can be an app's browser path", path)
	}
	if protocol.ValidAppName("webhooks") {
		t.Error("an app can be named webhooks")
	}
}
