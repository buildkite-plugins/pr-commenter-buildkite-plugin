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
	commenter := comment.NewCommenter(client)

	message, found := os.LookupEnv(common.PluginPrefix + "MESSAGE")
	if !found {
		fullStepURL := fmt.Sprintf("%s#%s", os.Getenv("BUILDKITE_BUILD_URL"), os.Getenv("BUILDKITE_JOB_ID"))
		message = fmt.Sprintf("[%s](%s) exited with code %s", fullStepURL, fullStepURL, os.Getenv("BUILDKITE_COMMAND_EXIT_STATUS"))
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
