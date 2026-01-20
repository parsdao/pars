// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/stretchr/testify/require"
)

func TestNewGraphVMClient(t *testing.T) {
	// Test with nil database
	t.Run("nil database", func(t *testing.T) {
		client := NewGraphVMClient(nil, nil)
		require.NotNil(t, client)
		require.Equal(t, uint64(0), client.ChainID())
	})

	// Test with real database
	t.Run("with database", func(t *testing.T) {
		db := memdb.New()
		defer db.Close()

		client := NewGraphVMClient(db, nil)
		require.NotNil(t, client)
		require.Equal(t, uint64(0), client.ChainID())
	})

	// Test with chain ID
	t.Run("with chain ID", func(t *testing.T) {
		db := memdb.New()
		defer db.Close()

		client := NewGraphVMClientWithChainID(db, nil, 96369)
		require.NotNil(t, client)
		require.Equal(t, uint64(96369), client.ChainID())
	})
}

func TestGraphVMClientQuery(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query should fail with disabled message
	result, err := client.Query(ctx, `query { chainInfo }`, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "functionality disabled")
	require.Nil(t, result)
}

func TestGraphVMClientQueryChain(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClientWithChainID(db, nil, 96369)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query should fail with disabled message
	result, err := client.QueryChain(ctx, 96369, `query { chainInfo }`, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "functionality disabled")
	require.Nil(t, result)
}

func TestGraphVMClientGetDB(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)
	require.Nil(t, client.GetDB())
}

func TestGraphVMClientSetChainID(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)
	require.Equal(t, uint64(0), client.ChainID())

	client.SetChainID(96369)
	require.Equal(t, uint64(96369), client.ChainID())
}

func TestGraphVMClientRegisterResolver(t *testing.T) {
	db := memdb.New()
	defer db.Close()

	client := NewGraphVMClient(db, nil)

	// Should not panic
	client.RegisterResolver("customQuery", nil)
}
