package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

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

	repoName, ok := os.LookupEnv("BUILDKITE_PULL_REQUEST_REPO")
	if !ok {
		repoName = os.Getenv("BUILDKITE_REPO")
	}
	owner, repo, err := repo.ParseRepo(repoName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing repo info: %s\n", err)
		return exitError
	}

	prNumber := os.Getenv("BUILDKITE_PULL_REQUEST")
	if prNumber == "false" {
		_, _ = fmt.Fprintf(os.Stdout, "Not a pull request. Exiting gracefully.\n")
		return exitOK
	}

	// If the build was canceled and message-path is configured but the file doesn't exist,
	// skip early before attempting secret retrieval which may be unavailable on canceled builds.
	if os.Getenv("BUILDKITE_COMMAND_EXIT_STATUS") == "-1" {
		if messagePath, found := os.LookupEnv(common.PluginPrefix + "MESSAGE_PATH"); found {
			if _, err := os.Stat(messagePath); os.IsNotExist(err) {
				fmt.Println("Build was canceled, skipping comment")
				return exitOK
			}
		}
	}

	secretName, found := os.LookupEnv(common.PluginPrefix + "SECRET_NAME")
	if !found {
		secretName = "GITHUB_TOKEN"
	}

	token, err := secret.GetSecret(secretName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secret: %s\n", err)
		return exitError
	}

	client, err := github.New(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating GitHub client: %s\n", err)
		return exitError
	}
	commenter, err := comment.NewCommenter(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error configuring commenter: %s\n", err)
		return exitError
	}

	message, found := os.LookupEnv(common.PluginPrefix + "MESSAGE")
	if !found {
		// Check if message-path has been set
		// and read in the provided file for the message content
		messagePath, found := os.LookupEnv(common.PluginPrefix + "MESSAGE_PATH")
		if found {
			m, err := os.ReadFile(messagePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading message-path file: %s\n", err)
				return exitError
			}
			message = string(m)
		} else {
			// at this point, neither message nor message-path are set
			// so just use a default message
			fullStepURL := fmt.Sprintf("%s#%s", os.Getenv("BUILDKITE_BUILD_URL"), os.Getenv("BUILDKITE_JOB_ID"))
			message = fmt.Sprintf("[%s](%s) exited with code %s", fullStepURL, fullStepURL, os.Getenv("BUILDKITE_COMMAND_EXIT_STATUS"))
		}
	}

	var allowRepeats = true
	// Allow for setting a "allow-repeats: false" plugin option to prevent duplicate comments
	allowRepeatsVal, found := os.LookupEnv(common.PluginPrefix + "ALLOW_REPEATS")
	if found {
		// if this fails, allowRepeats val will just be the default (true)
		allowRepeats, _ = strconv.ParseBool(allowRepeatsVal)
	}

	// Check for existing comment using the internal "message id", and update body if necessary
	if !allowRepeats {
		comment, err := commenter.FindExistingComment(ctx, owner, repo, prNumber)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching existing comments: %s\n", err)
			return exitError
		}
		if comment != nil {
			// existing comment found, check comment body for exact match
			// and update if body/message has changed
			if commenter.MatchBody(ctx, comment, message) {
				// Comment body/message unchanged, no action needed
				_, _ = fmt.Fprintf(os.Stdout, "Found matching comment: %s\n", *comment.HTMLURL)
			} else {
				// Body does not match, update comment
				err = commenter.UpdateComment(ctx, owner, repo, message, *comment.ID)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error updating existing comment %s: %s\n", *comment.HTMLURL, err)
					return exitError
				}
				_, _ = fmt.Fprintf(os.Stdout, "Updated matching comment: %s\n", *comment.HTMLURL)
			}
			return exitOK
		}
	}

	// If we're here, we didn't find an existing comment or allowRepeats is true (ie. post duplicate comments)
	// Post a new comment
	err = commenter.Post(ctx, owner, repo, prNumber, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error posting comment: %s\n", err)
	}

	fmt.Println("Comment posted successfully")
	return exitOK
}
