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

package anauth

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/emmyzkp/emmy/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var logger log.Logger

// FIXME
// init instantiates and configures client logger with default log level.
func init() {
	clientLogger, err := log.NewStdoutLogger("client", log.INFO, log.FORMAT_SHORT)
	if err != nil {
		panic(err)
	}
	logger = clientLogger
}

// GetLogger returns the instance of log.Logger currently configured for this package.
func GetLogger() log.Logger {
	return logger
}

// SetLogger assigns the log.Logger instance passed as argument to the logger of this package.
// This is to support loggers other than log.StdoutLogger, which is set as default in init function.
func SetLogger(lgr log.Logger) {
	logger = lgr
}

type connOptions struct {
	caCert             []byte
	serverNameOverride string
	timeoutMillis      int
}

var DEFAULT_TIMEOUT_MILLIS = 5000
var defaultConnOptions = connOptions{
	serverNameOverride: "", // don't override by default
	timeoutMillis:      DEFAULT_TIMEOUT_MILLIS,
}

// ConnOption is used to configure a connection to the server.
type ConnOption func(*connOptions)

// WithCACert sets the CA certificate for validating the server
// and returns the ConnOption.
func WithCACert(caCert []byte) ConnOption {
	return func(opts *connOptions) {
		opts.caCert = caCert
	}
}

// WithServerNameOverride sets the string that will be compared to the
// CN field from server's cert during validation, and returns the ConnOption.
// This allows validation to pass even if server's hostname differs from
// certificate's CN.
func WithServerNameOverride(override string) ConnOption {
	return func(opts *connOptions) {
		opts.serverNameOverride = override
	}
}

// WithTimeout sets a timeout in milliseconds for establishing initial
// connection with the server.
func WithTimeout(millis int) ConnOption {
	return func(opts *connOptions) {
		opts.timeoutMillis = millis
	}
}

// FIXME leave for now, but remove asap and let the client configure whichever
// conn he prefers

// GetConnection accepts address addr where a gRPC server is listening, and
// ConnOptions to configure the connection.
// It returns a connection that a client can use to contact the server or
// error in case of misconfiguration. // FIXME
//
// Note that several clients can be passed the same connection, as the gRPC
// framework is able to multiplex several RPCs on the same connection,
// thus reducing the overhead.
func GetConnection(addr string, opts ...ConnOption) (*grpc.ClientConn,
	error) {
	// configure according to provided configuration options, or use defaults
	cfg := defaultConnOptions
	for _, opt := range opts {
		opt(&cfg)
	}

	var creds credentials.TransportCredentials
	var err error
	// If the client doesn't explicitly provide a CA certificate,
	// build TLS credentials with the hosts' system certificate pool
	if cfg.caCert == nil {
		creds, err = getTLSCredsFromSysCertPool()
		if err != nil {
			return nil, fmt.Errorf("error creating TLS client credentials: %s", err)
		}
	} else {
		// If the client provided a CA certificate, he can still allow a mismatch in the server's
		// name and server's CN in certificate
		if cfg.serverNameOverride != "" {
		}
		creds, err = getTLSCreds(cfg.caCert, cfg.serverNameOverride)
		if err != nil {
			return nil, fmt.Errorf("error creating TLS client credentials: %s", err)
		}
	}
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithTimeout(time.Duration(cfg.timeoutMillis) * time.Millisecond),
	}
	conn, err := grpc.Dial(addr, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("could not connect to server %v (%v)", addr, err)
	}
	return conn, nil
}

// getTLSCreds generates TLS credentials that the client can use to contact the
// server via TLS. GrpcServer's certificate (in PEM format) will always be validated against the
// provided caCert.
// If serverNameOverride == "", certificate validation will include a check that server's hostname
// 	matches the common name (CN) in server's certificate.
// If serverNameOverride != "", the provided serverNameOverride must match server certificate's
//	CN in order for certificate validation to succeed. This can be used for testing and development
//	purposes, where server's CN does not resolve to a real domain and doesn't.
func getTLSCreds(caCert []byte, serverNameOverride string) (credentials.TransportCredentials,
	error) {
	certPool := x509.NewCertPool()
	// Try to append the provided caCert to the cert pool
	if success := certPool.AppendCertsFromPEM(caCert); !success {
		return nil, fmt.Errorf("cannot append certs from PEM")
	}

	return credentials.NewClientTLSFromCert(certPool, serverNameOverride), nil
}

// getTLSCredsFromSysCertPool retrieves TLS credentials based on host's system certificate
// pool. This function should be used when the client does not provide a specific CA certificate
// for validation of the target server.
func getTLSCredsFromSysCertPool() (credentials.TransportCredentials, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve system cert pool (%s)", err)
	}

	return credentials.NewClientTLSFromCert(certPool, ""), nil
}
