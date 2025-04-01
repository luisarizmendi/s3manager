package main

import (
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cloudlena/adapters/logging"
	"github.com/cloudlena/s3manager/internal/app/s3manager"
	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/spf13/viper"
)

//go:embed web/template
var templateFS embed.FS

//go:embed web/static
var staticFS embed.FS

type configuration struct {
	Endpoint            string
	UseIam              bool
	IamEndpoint         string
	AccessKeyID         string
	SecretAccessKey     string
	Region              string
	AllowDelete         bool
	ForceDownload       bool
	UseSSL              bool
	SkipSSLVerification bool
	SignatureType       string
	ListRecursive       bool
	Port                string
	Timeout             int32
	SseType             string
	SseKey              string
	BucketName          string // Parameter for limiting to a single bucket
}

func parseConfiguration() configuration {
	var accessKeyID, secretAccessKey, iamEndpoint string

	viper.AutomaticEnv()

	viper.SetDefault("ENDPOINT", "s3.amazonaws.com")
	endpoint := viper.GetString("ENDPOINT")

	useIam := viper.GetBool("USE_IAM")

	if useIam {
		iamEndpoint = viper.GetString("IAM_ENDPOINT")
	} else {
		accessKeyID = viper.GetString("ACCESS_KEY_ID")
		if len(accessKeyID) == 0 {
			log.Fatal("please provide ACCESS_KEY_ID")
		}

		secretAccessKey = viper.GetString("SECRET_ACCESS_KEY")
		if len(secretAccessKey) == 0 {
			log.Fatal("please provide SECRET_ACCESS_KEY")
		}
	}

	region := viper.GetString("REGION")

	viper.SetDefault("ALLOW_DELETE", true)
	allowDelete := viper.GetBool("ALLOW_DELETE")

	viper.SetDefault("FORCE_DOWNLOAD", true)
	forceDownload := viper.GetBool("FORCE_DOWNLOAD")

	viper.SetDefault("USE_SSL", true)
	useSSL := viper.GetBool("USE_SSL")

	viper.SetDefault("SKIP_SSL_VERIFICATION", false)
	skipSSLVerification := viper.GetBool("SKIP_SSL_VERIFICATION")

	viper.SetDefault("SIGNATURE_TYPE", "V4")
	signatureType := viper.GetString("SIGNATURE_TYPE")

	listRecursive := viper.GetBool("LIST_RECURSIVE")

	viper.SetDefault("PORT", "8080")
	port := viper.GetString("PORT")

	viper.SetDefault("TIMEOUT", 600)
	timeout := viper.GetInt32("TIMEOUT")

	viper.SetDefault("SSE_TYPE", "")
	sseType := viper.GetString("SSE_TYPE")

	viper.SetDefault("SSE_KEY", "")
	sseKey := viper.GetString("SSE_KEY")

	viper.SetDefault("BUCKET_NAME", "")
	bucketName := viper.GetString("BUCKET_NAME")

	return configuration{
		Endpoint:            endpoint,
		UseIam:              useIam,
		IamEndpoint:         iamEndpoint,
		AccessKeyID:         accessKeyID,
		SecretAccessKey:     secretAccessKey,
		Region:              region,
		AllowDelete:         allowDelete,
		ForceDownload:       forceDownload,
		UseSSL:              useSSL,
		SkipSSLVerification: skipSSLVerification,
		SignatureType:       signatureType,
		ListRecursive:       listRecursive,
		Port:                port,
		Timeout:             timeout,
		SseType:             sseType,
		SseKey:              sseKey,
		BucketName:          bucketName,
	}
}

// Create a middleware that checks if the requested bucket matches the configured one
func bucketRestrictionMiddleware(allowedBucket string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no specific bucket is configured, allow all
			if allowedBucket == "" {
				next.ServeHTTP(w, r)
				return
			}

			vars := mux.Vars(r)
			requestedBucket := vars["bucketName"]

			// If this is not a bucket-specific route, proceed
			if requestedBucket == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the requested bucket matches the allowed one
			if requestedBucket != allowedBucket {
				http.Error(w, "Access to this bucket is not allowed", http.StatusForbidden)
				return
			}

			// Bucket is allowed, proceed with the request
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	configuration := parseConfiguration()

	sseType := s3manager.SSEType{Type: configuration.SseType, Key: configuration.SseKey}
	serverTimeout := time.Duration(configuration.Timeout) * time.Second

	// Set up templates
	templates, err := fs.Sub(templateFS, "web/template")
	if err != nil {
		log.Fatal(err)
	}
	// Set up statics
	statics, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		log.Fatal(err)
	}

	// Set up S3 client
	opts := &minio.Options{
		Secure: configuration.UseSSL,
	}
	if configuration.UseIam {
		opts.Creds = credentials.NewIAM(configuration.IamEndpoint)
	} else {
		var signatureType credentials.SignatureType

		switch configuration.SignatureType {
		case "V2":
			signatureType = credentials.SignatureV2
		case "V4":
			signatureType = credentials.SignatureV4
		case "V4Streaming":
			signatureType = credentials.SignatureV4Streaming
		case "Anonymous":
			signatureType = credentials.SignatureAnonymous
		default:
			log.Fatalf("Invalid SIGNATURE_TYPE: %s", configuration.SignatureType)
		}

		opts.Creds = credentials.NewStatic(configuration.AccessKeyID, configuration.SecretAccessKey, "", signatureType)
	}

	if configuration.Region != "" {
		opts.Region = configuration.Region
	}
	if configuration.UseSSL && configuration.SkipSSLVerification {
		opts.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	s3, err := minio.New(configuration.Endpoint, opts)
	if err != nil {
		log.Fatalln(fmt.Errorf("error creating s3 client: %w", err))
	}

	// Check if specified bucket exists
	if configuration.BucketName != "" {
		exists, err := s3.BucketExists(context.Background(), configuration.BucketName)
		if err != nil {
			log.Printf("Error checking if bucket exists: %v", err)
		}
		
		if !exists {
			log.Printf("Warning: Specified bucket '%s' does not exist", configuration.BucketName)
		}
	}

	// Set up router with bucket restriction middleware
	r := mux.NewRouter()
	r.Use(bucketRestrictionMiddleware(configuration.BucketName))
	
	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.FS(statics)))).Methods(http.MethodGet)
	
	// Configure redirects and views based on bucket configuration
	if configuration.BucketName != "" {
		// If specific bucket is configured, redirect root and /buckets to that bucket
		r.Handle("/", http.RedirectHandler("/buckets/"+configuration.BucketName, http.StatusPermanentRedirect)).Methods(http.MethodGet)
		r.Handle("/buckets", http.RedirectHandler("/buckets/"+configuration.BucketName, http.StatusPermanentRedirect)).Methods(http.MethodGet)
	} else {
		// Default behavior - show buckets list
		r.Handle("/", http.RedirectHandler("/buckets", http.StatusPermanentRedirect)).Methods(http.MethodGet)
		r.Handle("/buckets", s3manager.HandleBucketsView(s3, templates, configuration.AllowDelete)).Methods(http.MethodGet)
	}
	
	// Bucket view routes - keep using {bucketName} parameter for handler compatibility
	r.Handle("/buckets/{bucketName}", s3manager.HandleBucketView(s3, templates, configuration.AllowDelete, configuration.ListRecursive)).Methods(http.MethodGet)
	r.Handle("/buckets/{bucketName}/{prefix:.*}", s3manager.HandleBucketView(s3, templates, configuration.AllowDelete, configuration.ListRecursive)).Methods(http.MethodGet)
	
	// API endpoints for bucket operations
	if configuration.BucketName == "" {
		// Only allow bucket creation if no specific bucket is specified
		r.Handle("/api/buckets", s3manager.HandleCreateBucket(s3)).Methods(http.MethodPost)
	}
	
	// API endpoints for object operations
	r.Handle("/api/buckets/{bucketName}/objects", s3manager.HandleCreateObject(s3, sseType)).Methods(http.MethodPost)
	r.Handle("/api/buckets/{bucketName}/objects/{objectName:.*}/url", s3manager.HandleGenerateUrl(s3)).Methods(http.MethodGet)
	r.Handle("/api/buckets/{bucketName}/objects/{objectName:.*}", s3manager.HandleGetObject(s3, configuration.ForceDownload)).Methods(http.MethodGet)
	
	// Delete operations if allowed
	if configuration.AllowDelete {
		if configuration.BucketName == "" {
			r.Handle("/api/buckets/{bucketName}", s3manager.HandleDeleteBucket(s3)).Methods(http.MethodDelete)
		}
		r.Handle("/api/buckets/{bucketName}/objects/{objectName:.*}", s3manager.HandleDeleteObject(s3)).Methods(http.MethodDelete)
	}

	lr := logging.Handler(os.Stdout)(r)
	srv := &http.Server{
		Addr:         ":" + configuration.Port,
		Handler:      lr,
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
	}
	
	if configuration.BucketName != "" {
		log.Printf("Starting S3 Manager with bucket limited to: %s", configuration.BucketName)
	} else {
		log.Printf("Starting S3 Manager with access to all buckets")
	}
	
	log.Fatal(srv.ListenAndServe())
}