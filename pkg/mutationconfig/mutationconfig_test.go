/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package mutationconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testMutationConfigsFile           = "../../testdata/mutationconfigs.yaml"
	testMutationConfigsWithParamsFile = "../../testdata/mutatingconfigs_with_params.yaml"
)

func TestMutationConfigs(t *testing.T) {
	mutationConfigs, err := NewMutatingConfigs(testMutationConfigsFile)
	assert.NoError(t, err)

	assert.Equal(t, "keymaker", mutationConfigs.MutationConfigs[0].Name)
}
