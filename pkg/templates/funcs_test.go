package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    interface{}
		wantErr bool
	}{
		{
			"invalid yaml",
			"'",
			nil,
			true,
		},
		{
			"empty object",
			"{}",
			map[interface{}]interface{}{},
			false,
		},
		{
			"raw string",
			"hello world",
			"hello world",
			false,
		},
		{
			"array of strings",
			`["hello", "goodbye"]`,
			[]interface{}{"hello", "goodbye"},
			false,
		},
		{
			"array of objects",
			`["hello", {}]`,
			[]interface{}{"hello", map[interface{}]interface{}{}},
			false,
		},
		{
			"top-level object",
			`age: "23"
hello: bar`,
			map[interface{}]interface{}{"age": "23", "hello": "bar"},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromYAML(tt.yaml)
			if tt.wantErr {
				require.Error(t, err, "Expected error unmarshalling yaml string")
				return
			}

			require.NoError(t, err, "Unexpected error unmarshalling yaml string")
			require.Equal(t, tt.want, got)
		})
	}
}
