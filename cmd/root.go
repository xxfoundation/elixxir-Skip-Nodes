////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package cmd

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
	"github.com/spf13/viper"
	"gitlab.com/elixxir/client/bindings"
	"gitlab.com/xx_network/comms/signature"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/utils"
	"os"
)

// Execute adds all child commands to the root command and sets flags
// appropriately.  This is called by main.main(). It only needs to
// happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "client",
	Short: "Sign a list of node IDs",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		signingKeyPath := viper.GetString("keyPath")
		inputCSVPath := viper.GetString("inputCSVPath")
		outputPath := viper.GetString("output")

		var signingKey []byte
		if ep, err := utils.ExpandPath(signingKeyPath); err == nil {
			signingKey, err = utils.ReadFile(ep)
			if err != nil {
				jww.ERROR.Panicf("Failed to read signing key at %s: %+v", ep, err)
			}
		} else {
			jww.ERROR.Panicf("Failed to expand signing key path %s: %+v", signingKeyPath, err)
		}

		var records [][]string
		if ep, err := utils.ExpandPath(inputCSVPath); err == nil {
			if f, err := os.Open(ep); err == nil {
				csvReader := csv.NewReader(f)
				records, err = csvReader.ReadAll()
				if err != nil {
					jww.ERROR.Panicf("Failed to read data from csv at %s: %+v", ep, err)
				}
			} else {
				jww.ERROR.Panicf("Failed to open input csv at %s: %+v", ep, err)
			}
		} else {
			jww.ERROR.Panicf("Failed to expand input CSV path %s: %+v", inputCSVPath, err)
		}

		var ids []*id.ID
		for _, row := range records {
			if len(row) > 1 {
				jww.WARN.Printf("Row contains more than one value: %+v", row)
			}
			b64Nid := row[0]
			idBytes, err := base64.StdEncoding.DecodeString(b64Nid)
			if err != nil {
				jww.ERROR.Panicf("Could not decode ID %s (ids are expected in base64): %+v", b64Nid, err)
			}
			nid, err := id.Unmarshal(idBytes)
			if err != nil {
				jww.ERROR.Panicf("Failed to unmarshal ID %s [%+v]: %+v", b64Nid, idBytes, err)
			}
			ids = append(ids, nid)
		}

		skipNodes := &bindings.SkipNodes{
			SkipNodes: ids,
		}
		fmt.Println(skipNodes)

		pk, err := rsa.LoadPrivateKeyFromPem(signingKey)
		if err != nil {
			jww.ERROR.Panicf("Failed to load private key from file %s: %+v", signingKeyPath, err)
		}
		err = signature.SignRsa(skipNodes, pk)
		if err != nil {
			jww.ERROR.Panicf("Failed to sign skip nodes object: %+v", err)
		}

		out, err := json.Marshal(skipNodes)
		if err != nil {
			jww.ERROR.Panicf("Failed to marshal object to JSON: %+v", err)
		}

		ep, err := utils.ExpandPath(outputPath)
		if err != nil {
			jww.ERROR.Panicf("Failed to expand output path %s: %+v", outputPath, err)
		}
		err = utils.WriteFile(ep, out, os.FileMode(0644), os.ModePerm)
		if err != nil {
			jww.ERROR.Panicf("Failed to write data to file at %s: %+v", ep, err)
		}
	}}

// init is the initialization function for Cobra which defines commands
// and flags.
func init() {
	// NOTE: The point of init() is to be declarative.
	// There is one init in each sub command. Do not put variable declarations
	// here, and ensure all the Flags are of the *P variety, unless there's a
	// very good reason not to have them as local params to sub command."
	rootCmd.PersistentFlags().StringP("keyPath", "k",
		"-", "Path to signing key")
	viper.BindPFlag("keyPath", rootCmd.PersistentFlags().Lookup(
		"keyPath"))

	rootCmd.PersistentFlags().StringP("inputCSVPath", "c",
		"-", "Path to input CSV")
	viper.BindPFlag("inputCSVPath", rootCmd.PersistentFlags().Lookup(
		"inputCSVPath"))
	viper.SetDefault("inputCSVPath", "ids.csv")

	rootCmd.PersistentFlags().StringP("output", "o",
		"-", "Path to output signed file")
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup(
		"output"))
	viper.SetDefault("output", "skipNodes.json")
}
