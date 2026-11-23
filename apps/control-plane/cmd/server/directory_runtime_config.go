package main

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/handler"
)

func loadDirectoryRuntime(getenv func(string) string) (handler.DirectoryRuntime, error) {
	config, err := directoryruntime.LoadConfig(directoryruntime.ConfigInput{
		RuntimeURL:         getenv("DIRECTORY_RUNTIME_URL"),
		AllowedRuntimeURLs: getenv("DIRECTORY_RUNTIME_ALLOWED_URLS"),
		ClientID:           getenv("DIRECTORY_RUNTIME_CLIENT_ID"),
		ClientSecret:       getenv("DIRECTORY_RUNTIME_CLIENT_SECRET"),
	})
	if err != nil {
		return nil, err
	}
	client, err := config.NewClient()
	if err != nil {
		return nil, err
	}
	return directoryruntime.NewOrchestrator(client), nil
}
