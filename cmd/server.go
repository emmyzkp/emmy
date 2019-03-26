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
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-redis/redis"

	"github.com/emmyzkp/emmy/anauth"
	"github.com/emmyzkp/emmy/anauth/cl"
	"github.com/emmyzkp/emmy/log"
)

var srv *anauth.GrpcServer
var port int
var keyPath string
var certPath string
var redisAddr string

var (
	clNKnownAttrs     int
	clNCommittedAttrs int
	clNHiddenAttrs    int
)

func init() {
	rootCmd.AddCommand(serverCmd, genCmd)

	serverCmd.PersistentFlags().IntVarP(&port, "port", "p",
		7007,
		"Port where emmy server will listen for client connections")
	serverCmd.PersistentFlags().StringVarP(&certPath, "cert", "c",
		"./anauth/test/testdata/server.pem",
		"Path to server's certificate file")
	serverCmd.PersistentFlags().StringVarP(&keyPath, "key", "k",
		"./anauth/test/testdata/server.key",
		"Path to server's key file")
	serverCmd.PersistentFlags().StringVarP(&redisAddr, "db", "",
		"localhost:6379",
		"URI of redis database to hold registration keys, in the form redisHost:redisPort")
	serverCmd.PersistentFlags().StringP("logfile", "",
		"",
		"Path to the file where server logs will be written ("+
			"created if it doesn't exist)")

	viper.BindPFlag("REDIS_ADDR", serverCmd.Flags().Lookup("db"))

	genCLCmd.Flags().IntVar(&clNKnownAttrs, "known", 0,
		"Number of known attributes")
	genCLCmd.Flags().IntVar(&clNCommittedAttrs, "committed", 0,
		"Number of known attributes")
	genCLCmd.Flags().IntVar(&clNHiddenAttrs, "hidden", 0,
		"Number of known attributes")
	_ = genCLCmd.MarkFlagRequired("known")

	viper.BindPFlag("CL_ATTRS_KNOWN", genCLCmd.Flags().Lookup("known"))
	viper.BindPFlag("CL_ATTRS_COMMITTED", genCLCmd.Flags().Lookup("committed"))
	viper.BindPFlag("CL_ATTRS_HIDDEN", genCLCmd.Flags().Lookup("hidden"))

	// add subcommands tied to various anonymous authentication schemes
	genCmd.AddCommand(genCLCmd)
	serverCmd.AddCommand(serverCLCmd, serverPsysCmd, serverECPsysCmd)
}

var genCmd = &cobra.Command{
	Use: "generate",
	Short: "Generates paremeters for the chosen anonymous authentication" +
		" scheme.",
}

var genCLCmd = &cobra.Command{
	Use:        "cl",
	Short:      "Generates and stores keypair for the scheme.",
	SuggestFor: []string{"cl"},
	Run: func(cmd *cobra.Command, args []string) {
		keys, err := cl.GenerateKeyPair(cl.GetDefaultParamSizes(),
			cl.NewAttrCount(clNKnownAttrs, clNCommittedAttrs, clNHiddenAttrs))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = cl.WriteGob(path.Join(emmyDir, "cl_seckey"), keys.Sec)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = cl.WriteGob(path.Join(emmyDir, "cl_pubkey"), keys.Pub)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("Successfully generated keypair")
	},
}

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts emmy anonymous authentication server",
	Long: `emmy server is a server (verifier) that verifies 
clients (provers).`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// FIXME make everything configurable
		lgr, err := log.NewStdoutLogger("cl", log.DEBUG, log.FORMAT_LONG)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		srv, err = anauth.NewGrpcServer(certPath, keyPath, lgr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if err := srv.Start(port); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

var serverCLCmd = &cobra.Command{
	Use: "cl",
	Short: "Configures the server to run Camenisch-Lysyanskaya scheme for" +
		" anonymous authentication.",
	Run: func(cmd *cobra.Command, args []string) {
		var sk cl.SecKey
		var pk cl.PubKey

		err := cl.ReadGob(path.Join(emmyDir, "cl_seckey"), &sk)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = cl.ReadGob(path.Join(emmyDir, "cl_pubkey"), &pk)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		redis := anauth.NewRedisClient(redis.NewClient(&redis.Options{
			Addr: redisAddr,
		}))
		if err := redis.Ping().Err(); err != nil {
			fmt.Println("cannot connect to redis:", err)
			os.Exit(1)
		}

		clService, err := cl.NewServer(
			cl.NewMockRecordManager(), // TODO redis
			&cl.KeyPair{
				Sec: &sk,
				Pub: &pk,
			}, viper.GetViper())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// FIXME
		clService.RegMgr = redis
		clService.SessMgr, _ = anauth.NewRandSessionKeyGen(32)
		clService.SessStorer = anauth.NewRedisSessStorer(redis.Client)
		clService.DataFetcher = cl.NewRedisDataFetcher(redis.Client)

		srv.RegisterService(clService)
	},
}

var serverPsysCmd = &cobra.Command{
	Use: "psys",
	Short: "Configures the server to run pseudonym system scheme for" +
		" anonymous authentication. Uses modular arithmetic.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running psys server")
	},
}

var serverECPsysCmd = &cobra.Command{
	Use: "ecpsys",
	Short: "Configures the server to run pseudonym system scheme for" +
		" anonymous authentication. Uses EC arithmetic.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("running ecpsys server")
	},
}
