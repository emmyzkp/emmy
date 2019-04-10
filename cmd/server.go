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

func init() {
	rootCmd.AddCommand(serverCmd, genCmd)

	serverCmd.PersistentFlags().IntP("port", "p",
		7007,
		"Port where emmy server will listen for client connections")
	serverCmd.PersistentFlags().StringP("cert", "c",
		"./anauth/test/testdata/server.pem",
		"Path to server's certificate file")
	serverCmd.PersistentFlags().StringP("key", "k",
		"./anauth/test/testdata/server.key",
		"Path to server's key file")
	serverCmd.PersistentFlags().StringP("db", "",
		"localhost:6379",
		"URI of redis database to hold registration keys, in the form redisHost:redisPort")
	serverCmd.PersistentFlags().StringP("logfile", "",
		"",
		"Path to the file where server logs will be written ("+
			"created if it doesn't exist)")

	genCLCmd.Flags().Int("known", 0, "Number of known attributes")
	genCLCmd.Flags().Int("committed", 0, "Number of committed attributes")
	genCLCmd.Flags().Int("hidden", 0, "Number of hidden attributes")

	// add subcommands tied to various anonymous authentication schemes
	genCmd.AddCommand(genCLCmd)
	serverCmd.AddCommand(serverCLCmd, serverPsysCmd, serverECPsysCmd)

	viper.BindPFlag("port", serverCmd.PersistentFlags().Lookup("port"))
	viper.BindPFlag("db", serverCmd.PersistentFlags().Lookup("db"))
	viper.BindPFlag("cert", serverCmd.PersistentFlags().Lookup("cert"))
	viper.BindPFlag("key", serverCmd.PersistentFlags().Lookup("key"))

	viper.BindPFlag("cl_n_known", genCLCmd.Flags().Lookup("known"))
	viper.BindPFlag("cl_n_committed", genCLCmd.Flags().Lookup("committed"))
	viper.BindPFlag("cl_n_hidden", genCLCmd.Flags().Lookup("hidden"))

	viper.SetEnvPrefix("EMMY")
	viper.BindEnv("db", "EMMY_REDIS_ADDR")
	viper.BindEnv("cert", "EMMY_TLS_CERT")
	viper.BindEnv("key", "EMMY_TLS_KEY")
	viper.BindEnv("cl_n_known", "EMMY_CL_N_KNOWN")
	viper.BindEnv("cl_n_committed", "EMMY_CL_N_COMMITTED")
	viper.BindEnv("cl_n_hidden", "EMMY_CL_N_HIDDEN")
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
			cl.NewAttrCount(
				viper.GetInt("cl_n_known"),
				viper.GetInt("cl_n_committed"),
				viper.GetInt("cl_n_hidden"),
			),
		)
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

		srv, err = anauth.NewGrpcServer(
			viper.GetString("cert"),
			viper.GetString("key"),
			lgr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if err := srv.Start(viper.GetInt("port")); err != nil {
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
			Addr: viper.GetString("db"),
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
