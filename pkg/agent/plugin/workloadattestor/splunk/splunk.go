package splunk

import "github.com/spiffe/spire/pkg/common/catalog"

const (
	pluginName = "splunk"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}
