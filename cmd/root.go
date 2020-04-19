package cmd

import "runtime"

import "github.com/google/gopacket/pcap"
import "github.com/spf13/cobra"
import "go.uber.org/zap"

// Version is version of the app
var Version = "unknown"

// Logging
var log *zap.SugaredLogger
var logConfig zap.Config

// Cobra
var rootCmd = &cobra.Command{
	Use:     "switch-bridge",
	Short:   "Wi-Fi Direct/Wi-Fi P2P bridge over IP",
	Version: Version + " [" + pcap.Version() + "] " + runtime.GOOS + "/" + runtime.GOARCH,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogging()
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		return log.Sync()
	},
}

// Flags
var debug = false

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	// Commands
	rootCmd.AddCommand(clientCmd)
	rootCmd.AddCommand(serverCmd)
}

func initLogging() error {
	logConfig = zap.NewDevelopmentConfig()
	if !debug {
		logConfig.Level.SetLevel(zap.InfoLevel)
	}
	zap, err := logConfig.Build()
	if err != nil {
		return err
	}
	log = zap.Sugar()
	return nil
}
