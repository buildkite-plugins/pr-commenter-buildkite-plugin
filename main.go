package main

import (
	"context"
	"fmt"
	"os"

	"prcommenter/internal/common"
	"prcommenter/internal/github"
	"prcommenter/internal/issue/comment"
	"prcommenter/internal/repo"
	"prcommenter/internal/secret"
)

type exitCode int

const (
	exitOK    exitCode = 0
	exitError exitCode = 1
)

func main() {
	err := run()
	os.Exit(int(err))
}

func run() exitCode {
	ctx := context.Background()

	owner, repo, err := repo.ParseRepo(os.Getenv("BUILDKITE_REPO"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing repo info: %v", err)
		return exitError
	}

	prNumber := os.Getenv("BUILDKITE_PULL_REQUEST")
	if prNumber == "false" {
		fmt.Fprintf(os.Stdout, "Not a pull request. Exiting gracefully.")
		return exitOK
	}

	secretName, found := os.LookupEnv(common.PluginPrefix + "SECRET_NAME")
	if !found {
		secretName = "GITHUB_TOKEN"
	}

	token, err := secret.GetSecret(secretName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secret: %v", err)
		return exitError
	}

	client, err := github.New(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating GitHub client: %v", err)
		return exitError
	}

	message, found := os.LookupEnv(common.PluginPrefix + "MESSAGE")
	if !found {
		fullStepURL := fmt.Sprintf("%s#%s", os.Getenv("BUILDKITE_BUILD_URL"), os.Getenv("BUILDKITE_JOB_ID"))
		message = fmt.Sprintf("[%s](%s) exited with code %s", fullStepURL, fullStepURL, os.Getenv("BUILDKITE_COMMAND_EXIT_STATUS"))
	}

	err = comment.Post(ctx, client, owner, repo, prNumber, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error posting comment: %v", err)
	}

	fmt.Println("Comment posted successfully")
	return exitOK
}
