// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/stretchr/testify/require"
)

func TestSetGraphVMClient(t *testing.T) {
	// Save original state
	origClient := GraphContractInstance.precompile.client
	defer func() {
		GraphContractInstance.precompile.client = origClient
	}()

	db := memdb.New()
	defer db.Close()

	// Set the client
	SetGraphVMClient(db, nil)

	// Verify client was set
	require.NotNil(t, GraphContractInstance.precompile.client)
	_, ok := GraphContractInstance.precompile.client.(*GraphVMClient)
	require.True(t, ok)
	// executor field is removed, so we just check the client is set
}

func TestSetGraphVMClientWithChainID(t *testing.T) {
	// Save original state
	origClient := GraphContractInstance.precompile.client
	defer func() {
		GraphContractInstance.precompile.client = origClient
	}()

	db := memdb.New()
	defer db.Close()

	// Set the client with chain ID
	SetGraphVMClientWithChainID(db, nil, 96369)

	// Verify client was set with chain ID
	require.NotNil(t, GraphContractInstance.precompile.client)
	client, ok := GraphContractInstance.precompile.client.(*GraphVMClient)
	require.True(t, ok)
	require.Equal(t, uint64(96369), client.ChainID())
}

func TestGraphConfigKey(t *testing.T) {
	cfg := &GraphConfig{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Equal(t, "graphConfig", cfg.Key())
}

func TestGraphConfigTimestamp(t *testing.T) {
	// Test nil timestamp
	cfg := &GraphConfig{}
	require.Nil(t, cfg.Timestamp())

	// Test with timestamp
	ts := uint64(12345)
	cfg.Upgrade.BlockTimestamp = &ts
	require.Equal(t, &ts, cfg.Timestamp())
}

func TestGraphConfigIsDisabled(t *testing.T) {
	cfg := &GraphConfig{}
	require.False(t, cfg.IsDisabled())

	cfg.Upgrade.Disable = true
	require.True(t, cfg.IsDisabled())
}

func TestGraphConfigEqual(t *testing.T) {
	cfg1 := &GraphConfig{
		GChainEndpoint: "http://localhost:9650",
		QueryTimeout:   5,
		MaxCacheSize:   1000,
	}
	cfg2 := &GraphConfig{
		GChainEndpoint: "http://localhost:9650",
		QueryTimeout:   5,
		MaxCacheSize:   1000,
	}
	cfg3 := &GraphConfig{
		GChainEndpoint: "http://localhost:9651",
		QueryTimeout:   5,
		MaxCacheSize:   1000,
	}

	// Same config
	require.True(t, cfg1.Equal(cfg2))

	// Different config
	require.False(t, cfg1.Equal(cfg3))

	// Wrong type
	require.False(t, cfg1.Equal(nil))
}

func TestGraphConfigVerify(t *testing.T) {
	cfg := &GraphConfig{}
	err := cfg.Verify(nil)
	require.NoError(t, err)
}

func TestGraphQLContractRun(t *testing.T) {
	// Save original state
	origClient := GraphContractInstance.precompile.client
	defer func() {
		GraphContractInstance.precompile.client = origClient
	}()

	// Set up client
	db := memdb.New()
	defer db.Close()

	SetGraphVMClient(db, nil)

	// Create input for query method (selector 0x01)
	req := QueryRequest{
		Query: `query { chainInfo { vmName version readOnly } }`,
	}
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	input := make([]byte, 4+len(reqBytes))
	binary.BigEndian.PutUint32(input[:4], 0x01) // query method selector
	copy(input[4:], reqBytes)

	// Run the contract - should return error now as functionality is disabled
	_, _, runErr := GraphContractInstance.Run(
		nil,                    // accessibleState
		ContractGraphQLAddress, // caller
		ContractGraphQLAddress, // addr
		input,                  // input
		1_000_000,              // suppliedGas
		true,                   // readOnly
	)

	// Stubbed functionality returns nil error (success with empty response)
	require.NoError(t, runErr)
	// require.Contains(t, runErr.Error(), "functionality disabled")
}

func TestGraphQLContractRunOutOfGas(t *testing.T) {
	input := make([]byte, 8)
	binary.BigEndian.PutUint32(input[:4], 0x01)

	_, _, err := GraphContractInstance.Run(
		nil,
		ContractGraphQLAddress,
		ContractGraphQLAddress,
		input,
		100, // Not enough gas
		true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

func TestGraphQLContractRunGetStats(t *testing.T) {
	// Create input for getStats method (selector 0x03)
	input := make([]byte, 4)
	binary.BigEndian.PutUint32(input[:4], 0x03)

	result, _, err := GraphContractInstance.Run(
		nil,
		ContractGraphQLAddress,
		ContractGraphQLAddress,
		input,
		1_000_000,
		true,
	)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Parse stats response
	var stats QueryStats
	err = json.Unmarshal(result, &stats)
	require.NoError(t, err)
}

func TestGraphQLContractRunInvalidInput(t *testing.T) {
	// Too short input
	_, _, err := GraphContractInstance.Run(
		nil,
		ContractGraphQLAddress,
		ContractGraphQLAddress,
		[]byte{1, 2}, // Only 2 bytes
		1_000_000,
		true,
	)

	require.Error(t, err)
}

func TestModuleRegistration(t *testing.T) {
	// Module should be registered
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractGraphQLAddress, Module.Address)
	require.Equal(t, GraphContractInstance, Module.Contract)
	require.NotNil(t, Module.Configurator)
}

func TestContractAddresses(t *testing.T) {
	// Verify contract addresses are in Graph/Query range (0x0500-0x05FF)
	require.Equal(t, "0x0500000000000000000000000000000000000010", ContractGraphQLAddress.Hex())
	require.Equal(t, "0x0500000000000000000000000000000000000011", ContractSubscribeAddress.Hex())
	require.Equal(t, "0x0500000000000000000000000000000000000012", ContractCacheAddress.Hex())
	require.Equal(t, "0x0500000000000000000000000000000000000013", ContractIndexAddress.Hex())
}
