package templates

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// FromYAML decodes a YAML string into an interface{}. This allows injection templates to access
// configs defined as YAML strings.
func FromYAML(str string) (interface{}, error) {
	var i interface{}

	if err := yaml.Unmarshal([]byte(str), &i); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml with error: %v. source: %q", err, str)
	}
	return i, nil
}
