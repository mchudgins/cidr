// Copyright © 2017 Mike Hudgins <mchudgins@gmail.com>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile         string
	withinFieldMask []int = []int{8, 8, 8, 8}
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "cidr",
	Short: "return a network address given a mask and a value",
	Long: `Calculate a network 'address' give a mask and a value.  This is useful
when dealing with the 172.16.0.0/12 CIDR or when subnets don't align
with octet boundaries.  Example:

	cidr --mask 12.8.6.6 --within 172.16.0.0 0.1.1.1

returns

	172.16.16.65
	`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			cmd.Usage()
			return
		}

		mask, err := cmd.Flags().GetString("mask")
		if err != nil {
			panic(err)
		}
		within, err := cmd.Flags().GetString("within")
		if err != nil {
			panic(err)
		}

		str, err := translate(args[0], mask, within)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		fmt.Printf("%s\n", str)

	},
}

// translate the inputs into a network value
func translate(value, mask, within string) (string, error) {

	//parse the mask
	fields, err := parse(mask)
	if err != nil {
		return "", err
	}

	// make sure the mask sums to 32
	sum := 0
	for _, i := range fields {
		sum += i
	}
	if sum != 32 {
		return "", fmt.Errorf("expected the mask to define 32 bits, only found %d", sum)
	}

	// parse the value
	values, err := parse(value)

	if len(fields) != len(values) {
		return "",
			fmt.Errorf("different number of fields in the mask(%d) and the value(%d)", len(fields), len(values))
	}

	netmask, err := computeCIDR(fields, values)
	if err != nil {
		return "", err
	}

	withinValues, err := parse(within)
	if len(withinFieldMask) != len(withinValues) {
		return "",
			fmt.Errorf("different number of fields in the mask(%d) and the value(%d)",
				len(withinFieldMask), len(withinValues))
	}
	withinCIDR, err := computeCIDR(withinFieldMask, withinValues)

	for i, x := range withinCIDR {
		netmask[i] = netmask[i] | x
	}

	var output string
	output = fmt.Sprintf("%d.%d.%d.%d",
		netmask[0],
		netmask[1],
		netmask[2],
		netmask[3])

	return output, nil
}

// parse a dotted set of integers into an an array of ints
// any non-numeric may be used as the separator
func parse(mask string) ([]int, error) {
	var sep string

	for _, c := range mask {
		if c < '0' || c > '9' {
			sep = string(c)
			break
		}
	}

	if len(sep) == 0 {
		return nil, fmt.Errorf("The mask '%s' has only one or no fields", mask)
	}

	str := strings.Split(mask, sep)
	fields := make([]int, len(str))

	for i, s := range str {
		var err error
		fields[i], err = strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("error parsing mask field '%s' -- %s", s, err)
		}
	}

	return fields, nil
}

// return 4 ints based on the fields & values provided
func computeCIDR(fields, values []int) ([]int, error) {

	var result uint32
	for i, f := range fields {
		var field uint32 = uint32(f)
		var uval uint32 = uint32(values[i])
		field = uval & generateAndMask(f)
		if field != uval {
			return nil, fmt.Errorf("field #%d (%d) exceeds the defined field length of %d", i, uval, f)
		}

		result = result << uint32(f)
		result = result | field
	}

	netmask := make([]int, 4)
	for i, _ := range netmask {
		index := len(netmask) - i - 1
		netmask[index] = int(result & 0x0ff)
		result = result >> 8
	}

	return netmask, nil
}

// generate a bitmask of 1's of the specified length
// (this seems overly brute force?)
func generateAndMask(length int) uint32 {
	var mask uint32

	mask = 0
	for i := 0; i < length; i++ {
		mask <<= 1
		mask |= 1
	}
	return mask
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cidr.yaml)")

	RootCmd.Flags().StringP("mask", "m", "8:13:4:7", "bitmask for translation")
	RootCmd.Flags().StringP("within", "w", "0.0.0.0", "result is OR'ed with this CIDR")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".cidr" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".cidr")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
