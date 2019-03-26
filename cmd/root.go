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

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var emmyDir string
var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "emmy",
	Short: "emmy CLI app allows you to run emmy server and emmy clients",
	Long: `emmy provides various schemes for anonymous authentication of
clients to the server.

Anonymous authentication typically comprises several steps in which the client 
(prover) proves his knowledge of an attribute to the server (verifier)
without revealing the value of the attribute.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default is $HOME/.emmy/config.yaml)")
	rootCmd.PersistentFlags().StringP("loglevel", "l",
		"info",
		"One of debug|info|notice|error|critical")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		dir, err := emmyDirectory()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		emmyDir = dir

		// Search config in emmy directory
		viper.AddConfigPath(emmyDir)
		viper.SetConfigType("yml")
		viper.SetConfigName("config")

		fmt.Printf("Using configuration directory '%s'\n", emmyDir)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Using config file:", viper.ConfigFileUsed())
}

// emmyDirectory checks whether emmy configuration directory
// exists on the filesystem. If it doesn't exist, it attemts
// to create it.
// It returns the path to emmy directory, or error in case
// of failure.
func emmyDirectory() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	emmyPath := path.Join(home, ".emmy")
	if _, err = os.Stat(emmyPath); !os.IsNotExist(err) {
		return emmyPath, nil
	}

	fmt.Println("Emmy directory doesn't exist, creating...")
	if err := os.Mkdir(emmyPath, 0744); err != nil {
		return "", err
	}

	return emmyPath, nil
}
