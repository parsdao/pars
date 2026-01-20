// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"context"
	"fmt"

	"github.com/luxfi/database"
)

// GraphVMClient implements GChainClient by wrapping a real query executor.
// This provides the bridge between the EVM precompile interface and the
// actual GraphVM query execution engine.
type GraphVMClient struct {
	chainID uint64 // The chain ID this client is connected to
}

// Ensure GraphVMClient implements GChainClient
var _ GChainClient = (*GraphVMClient)(nil)

// NewGraphVMClient creates a new GraphVMClient.
// Note: GraphVM functionality is currently disabled due to missing dependency.
func NewGraphVMClient(db database.Database, config interface{}) *GraphVMClient {
	return &GraphVMClient{
		chainID: 0, // Default to local/primary chain
	}
}

// NewGraphVMClientWithChainID creates a client for a specific chain ID.
func NewGraphVMClientWithChainID(db database.Database, config interface{}, chainID uint64) *GraphVMClient {
	return &GraphVMClient{
		chainID: chainID,
	}
}

// Query executes a GraphQL query against the GraphVM.
func (c *GraphVMClient) Query(ctx context.Context, query string, variables map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("GraphVM client not initialized (functionality disabled)")
}

// QueryChain executes a query against a specific chain.
func (c *GraphVMClient) QueryChain(ctx context.Context, chainID uint64, query string, variables map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("GraphVM client not initialized (functionality disabled)")
}

// GetDB returns the underlying database.
func (c *GraphVMClient) GetDB() database.Database {
	return nil
}

// RegisterResolver allows adding custom resolvers.
func (c *GraphVMClient) RegisterResolver(name string, resolver interface{}) {
	// No-op
}

// ChainID returns the chain ID this client is connected to.
func (c *GraphVMClient) ChainID() uint64 {
	return c.chainID
}

// SetChainID updates the chain ID for this client.
func (c *GraphVMClient) SetChainID(chainID uint64) {
	c.chainID = chainID
}
