/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package compat

import (
	"github.com/emmyzkp/emmy/anauth"
	"google.golang.org/grpc"
)

// ConnectionConfig wraps client.ConnectionConfig that holds connection information.
// Clients need to provide these information in order to establish connection to the server.
// For more details see documentation for the github.com/emmyzkp/emmy/client package.
type ConnectionConfig struct {
	Endpoint           string // Server's Endpoint
	ServerNameOverride string
	CACertificate      []byte
	TimeoutMillis      int
}

// NewConnectionConfig constructs an instance of ConnectionConfig based on the provided server
// endpoint, serverNameOverride and CA certificate.
func NewConnectionConfig(endpoint, serverNameOverride string,
	certificate []byte, timeout int) *ConnectionConfig {
	return &ConnectionConfig{
		endpoint,
		serverNameOverride,
		certificate,
		timeout,
	}
}

// Connection wraps *grpc.ClientConn. A Connection should be constructed independently and then
// passed as an argument to protocol clients. Same Connection can be re-used for many clients.
type Connection struct {
	*grpc.ClientConn
}

// NewConnection accepts *ConnectionConfig and uses the provided configuration information to
// establish connection to the server.
func NewConnection(cfg *ConnectionConfig) (*Connection, error) {
	conn, err := anauth.GetConnection(cfg.Endpoint, []anauth.ConnOption{
		anauth.WithCACert(cfg.CACertificate),
		anauth.WithServerNameOverride(cfg.ServerNameOverride),
		anauth.WithTimeout(cfg.TimeoutMillis)}...)

	if err != nil {
		return nil, err
	}

	return &Connection{conn}, err
}

// Close attempts to close connection to the server.
func (c *Connection) Close() error {
	if err := c.ClientConn.Close(); err != nil {
		return err
	}

	return nil
}
