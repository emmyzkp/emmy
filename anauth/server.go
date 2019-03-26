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
	"fmt"
	"math"
	"net"
	"net/http"

	"github.com/emmyzkp/emmy/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GrpcServer struct {
	*grpc.Server
	Logger log.Logger

	creds   credentials.TransportCredentials
	service Service
}

// Service registers a grpc service handler to
// a grpc.GrpcServer passed as argument.
type Service interface {
	RegisterTo(*grpc.Server)
}

// RegisterService registers a Service service to the underlying
// gRPC server. It returns an error if a service is already registered.
func (s *GrpcServer) RegisterService(r Service) error {
	if s.service != nil {
		return fmt.Errorf("anonymous authentication service is" +
			" already registered")
	}
	r.RegisterTo(s.Server)
	return nil
}

// NewGrpcServer initializes an instance of the GrpcServer struct and returns a pointer.
// It performs some default configuration (tracing of gRPC communication and interceptors)
// and registers RPC server handlers with gRPC server. It requires TLS cert and keyfile
// in order to establish a secure channel with clients.
func NewGrpcServer(certFile, keyFile string, logger log.Logger) (*GrpcServer, error) {
	// TODO check for nil logger?
	logger.Info("Instantiating new server")

	// Obtain TLS credentials
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create TLS credentials")
	}

	logger.Infof("Successfully read certificate [%s] and key [%s]", certFile, keyFile)

	// Allow as much concurrent streams as possible and register a gRPC stream interceptor
	// for logging and monitoring purposes.
	s := &GrpcServer{
		Server: grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxConcurrentStreams(math.MaxUint32),
		),
		Logger: logger,
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via GrpcServer's EnableTracing function.
	grpc.EnableTracing = false

	return s, nil
}

// Start configures and starts the protocol server at the requested port.
func (s *GrpcServer) Start(port int) error {
	connStr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		return fmt.Errorf("could not connect: %v", err)
	}

	// RegisterTo Prometheus metrics handler and serve metrics page on the desired endpoint.
	// Metrics are handled via HTTP in a separate goroutine as gRPC requests,
	// as grpc server's performance over HTTP (GrpcServer.ServeHTTP) is much worse.
	http.Handle("/metrics", prometheus.Handler())

	// After this, /metrics will be available, along with /debug/requests, /debug/events in
	// case server's EnableTracing function is called.
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	s.Logger.Noticef("Emmy server listening for connections on port %d", port)
	s.Server.Serve(listener)
	return nil
}

// Teardown stops the protocol server by gracefully stopping enclosed gRPC server.
func (s *GrpcServer) Teardown() {
	s.Logger.Notice("Tearing down gRPC server")
	s.Server.GracefulStop()
}

// EnableTracing instructs the gRPC framework to enable its tracing capability, which
// is mainly used for debugging purposes.
// Although this function does not explicitly affect the GrpcServer struct, it is wired to GrpcServer
// in order to provide a nicer API when setting up the server.
func (s *GrpcServer) EnableTracing() {
	grpc.EnableTracing = true
	s.Logger.Notice("Enabled gRPC tracing")
}
