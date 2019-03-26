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

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Runs emmy client against emmy server",
	//Usage: ``
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Unimplemented, coming soon")
	},
}

var clientCLCmd = &cobra.Command{
	Use: "cl",
	Short: "Configures emmy client to run Camenisch-Lysyanskaya scheme for" +
		" anonymous authentication",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running CL client")
	},
}

var clientPsysCmd = &cobra.Command{
	Use: "psys",
	Short: "Configures emmy client to run pseudonym system scheme for" +
		" anonymous authentication. Uses modular arithmetic",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running psys server")
	},
}

var clientECPsysCmd = &cobra.Command{
	Use: "ecpsys",
	Short: "Configures emmy client to run pseudonym system scheme for" +
		" anonymous authentication. Uses EC arithmetic.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running ecpsys server")
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)

	// Points to the endpoint at which emmy clients will
	// contact emmy server.
	clientCmd.PersistentFlags().StringP("server", "s",
		"localhost:7007",
		"URI of emmy server in the form host:port")
	// Indicates the number of (either concurrent or sequential)
	// clients to run.
	clientCmd.PersistentFlags().IntP("nclients", "n",
		1,
		"How many clients to run")
	// Allows the client to skip validation of the server's hostname when
	// checking its CN. Instead, CN from the server's certificate must match
	// the value indicated by the flag.
	clientCmd.PersistentFlags().StringP("servername", "",
		"",
		"Name of emmy server for overriding the server name stated in cert"+
			"'s CN")
	// Whether to run clients concurrently. Relevant only when nclients > 1.
	clientCmd.PersistentFlags().BoolP("concurrent", "",
		false,
		"Whether to run clients concurrently (when nclients > 1)")
	// Indicates the timeout (in seconds) for establishing connection to the
	// server. If connection cannot be established before the timeout,
	// the client fails.
	clientCmd.PersistentFlags().IntP("timeout", "t",
		5,
		"timeout (in seconds) for establishing connection with the server")
	// Keeps the path to CA's certificate in PEM format,
	// for establishing a secure channel with the server).
	clientCmd.PersistentFlags().StringP("cacert", "",
		"",
		`Path to certificate file of the CA that issued emmy server's
certificate, in PEM format`)
	// Indicates whether a client should use system's certificate pool to
	// validate the server's certificate..
	clientCmd.PersistentFlags().BoolP("syscertpool", "",
		false,
		"Whether to use host system's certificate pool to validate the server")

	clientCmd.AddCommand(clientCLCmd, clientPsysCmd, clientECPsysCmd)
}
