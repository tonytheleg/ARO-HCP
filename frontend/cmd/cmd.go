package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	sdk "github.com/openshift-online/ocm-sdk-go"
	"github.com/openshift-online/ocm-sdk-go/authentication"
	"github.com/spf13/cobra"

	"github.com/Azure/ARO-HCP/frontend/pkg/config"
	"github.com/Azure/ARO-HCP/frontend/pkg/database"
	"github.com/Azure/ARO-HCP/frontend/pkg/frontend"
)

const oauthClientID = "ocm-cli"

type FrontendOpts struct {
	clustersServiceURL      string
	clustersServiceTokenURL string
	useAuthCode             bool
	insecure                bool

	region string
	port   int

	databaseName string
	databaseURL  string
}

func NewRootCmd() *cobra.Command {
	opts := &FrontendOpts{}
	rootCmd := &cobra.Command{
		Use:   "frontend",
		Short: "TODO",
		Args:  cobra.NoArgs,
		Long:  "TODO",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}

	rootCmd.Flags().StringVar(&opts.databaseName, "database-name", os.Getenv("DB_NAME"), "database name")
	rootCmd.Flags().StringVar(&opts.databaseURL, "database-url", os.Getenv("DB_URL"), "database url")
	rootCmd.Flags().StringVar(&opts.region, "region", os.Getenv("REGION"), "Azure region")
	rootCmd.Flags().IntVar(&opts.port, "port", 8443, "port to listen on")

	rootCmd.Flags().BoolVar(&opts.useAuthCode, "use-auth-code", false, "Login using OAuth Authorization Code. This should be used for most cases where a browser is available.")
	rootCmd.Flags().StringVar(&opts.clustersServiceURL, "clusters-service-url", "https://api.openshift.com", "URL of the OCM API gateway.")
	rootCmd.Flags().StringVar(&opts.clustersServiceTokenURL, "clusters-service-token-url", "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token", "OpenID token URL.")
	rootCmd.Flags().BoolVar(&opts.insecure, "insecure", false, "Skip validating TLS for clusters-service.")

	return rootCmd
}

func (opts *FrontendOpts) Run() error {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				version = setting.Value
				break
			}
		}
	}

	logger := config.DefaultLogger()
	logger.Info(fmt.Sprintf("%s (%s) started", frontend.ProgramName, version))

	// Init prometheus emitter
	prometheusEmitter := frontend.NewPrometheusEmitter()

	// Configure database configuration and client
	dbConfig := database.NewDatabaseConfig(opts.databaseName, opts.databaseURL)
	dbClient, err := database.NewDatabaseClient(dbConfig)
	if err != nil {
		return fmt.Errorf("creating the database client failed: %v", err)
	}

	listener, err := net.Listen("tcp4", fmt.Sprintf(":%d", opts.port))
	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Application running in region: %s", opts.region))

	// Initialize Clusters Service Client
	conn, err := opts.InitClustersServiceConn(logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Connection to CS failed: %v", err))
	}

	f := frontend.NewFrontend(logger, listener, prometheusEmitter, dbClient, opts.region, conn)

	// Verify the Async DB is available and accessible
	logger.Info("Testing DB Access")
	result, err := f.DbClient.DBConnectionTest(context.Background())
	if err != nil {
		logger.Error(fmt.Sprintf("Database test failed to fetch properties: %v", err))
	} else {
		logger.Info(fmt.Sprintf("Database check completed - %s", result))
	}

	stop := make(chan struct{})
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go f.Run(context.Background(), stop)

	sig := <-signalChannel
	logger.Info(fmt.Sprintf("caught %s signal", sig))
	close(stop)

	f.Join()
	logger.Info(fmt.Sprintf("%s (%s) stopped", frontend.ProgramName, version))

	return nil
}

func (opts *FrontendOpts) InitClustersServiceConn(logger *slog.Logger) (*sdk.Connection, error) {
	conn := sdk.NewConnectionBuilder()

	if opts.useAuthCode {
		logger.Info("redirecting to Red Hat SSO login")
		token, err := authentication.InitiateAuthCode(oauthClientID)
		if err != nil {
			return nil, fmt.Errorf("an error occurred while retrieving the token : %v", err)
		}

		conn = conn.Tokens(token)
	}

	return conn.
		URL(opts.clustersServiceURL).
		Client(oauthClientID, "").
		TokenURL(opts.clustersServiceTokenURL).
		Insecure(opts.insecure).
		Build()
}
