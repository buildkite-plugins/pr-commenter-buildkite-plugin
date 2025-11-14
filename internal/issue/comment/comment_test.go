package comment_test

import (
	"context"
	"testing"

	"prcommenter/internal/common"
	"prcommenter/internal/issue/comment"

	"github.com/google/go-github/github"
)

type mockGitHubClient struct {
	createComment func(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
	listComments  func(ctx context.Context, owner string, repo string, number int, opts *github.IssueListCommentsOptions) ([]*github.IssueComment, *github.Response, error)
	editComment   func(ctx context.Context, owner, repo string, commentID int64, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
}

func (m *mockGitHubClient) CreateComment(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
	return m.createComment(ctx, owner, repo, number, comment)
}

func (m *mockGitHubClient) ListComments(ctx context.Context, owner string, repo string, number int, opts *github.IssueListCommentsOptions) ([]*github.IssueComment, *github.Response, error) {
	return m.listComments(ctx, owner, repo, number, opts)
}

func (m *mockGitHubClient) EditComment(ctx context.Context, owner, repo string, commentID int64, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
	return m.editComment(ctx, owner, repo, commentID, comment)
}

func TestPost(t *testing.T) {
	t.Setenv("BUILDKITE_PIPELINE_SLUG", "test-pipeline")
	t.Setenv("BUILDKITE_LABEL", "test-label")
	t.Setenv(common.PluginPrefix+"MESSAGE_ID", "1")

	mockClient := &mockGitHubClient{
		createComment: func(ctx context.Context, owner, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
			if owner != "testdev" || repo != "hello" || number != 420 || *comment.Body != "Test comment\n\n<!-- test-pipeline:test-label:pr-commenter-buildkite-plugin:1 -->" {
				t.Errorf("Unexpected arguments: owner=%s, repo=%s, number=%d, body=%s", owner, repo, number, *comment.Body)
			}
			return nil, nil, nil
		},
	}

	commenter := comment.NewCommenter(mockClient)

	err := commenter.Post(context.Background(), "testdev", "hello", "420", "Test comment")
	if err != nil {
		t.Fatalf("error posting comment: %s", err)
	}
}

func TestPostCommentEmptyBody(t *testing.T) {
	mockClient := &mockGitHubClient{}
	commenter := comment.NewCommenter(mockClient)

	err := commenter.Post(context.Background(), "testdev", "hello", "69", "")
	if err == nil {
		t.Fatalf("error expected due to empty body")
	}
}

func TestFindExistingComment_Found(t *testing.T) {
	t.Setenv("BUILDKITE_PIPELINE_SLUG", "test-pipeline")
	t.Setenv("BUILDKITE_LABEL", "test-label")
	t.Setenv(common.PluginPrefix+"MESSAGE_ID", "1")

	expectedID := int64(123)
	expectedBody := "Test comment\n\n<!-- test-pipeline:test-label:pr-commenter-buildkite-plugin:1 -->"
	expectedURL := "https://github.com/test/repo/pull/1#issuecomment-123"

	mockClient := &mockGitHubClient{
		listComments: func(ctx context.Context, owner, repo string, number int, opts *github.IssueListCommentsOptions) ([]*github.IssueComment, *github.Response, error) {
			if owner != "testdev" || repo != "hello" || number != 320 {
				t.Errorf("Unexpected arguments: owner=%s, repo=%s, number=%d", owner, repo, number)
			}
			return []*github.IssueComment{
				{
					ID:      &expectedID,
					Body:    &expectedBody,
					HTMLURL: &expectedURL,
				},
			}, nil, nil
		},
	}

	commenter := comment.NewCommenter(mockClient)
	result, err := commenter.FindExistingComment(context.Background(), "testdev", "hello", "320")

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result == nil {
		t.Fatal("expected comment to be found, got nil")
	}
	if *result.ID != expectedID {
		t.Errorf("expected ID %d, got %d", expectedID, *result.ID)
	}
}

func TestUpdateComment_Success(t *testing.T) {
	t.Setenv("BUILDKITE_PIPELINE_SLUG", "test-pipeline")
	t.Setenv("BUILDKITE_LABEL", "test-label")
	t.Setenv(common.PluginPrefix+"MESSAGE_ID", "1")

	commentID := int64(456)
	expectedBody := "Updated comment\n\n<!-- test-pipeline:test-label:pr-commenter-buildkite-plugin:1 -->"

	mockClient := &mockGitHubClient{
		editComment: func(ctx context.Context, owner, repo string, id int64, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
			if owner != "testdev" || repo != "hello" || id != commentID {
				t.Errorf("Unexpected arguments: owner=%s, repo=%s, commentID=%d", owner, repo, id)
			}
			if *comment.Body != expectedBody {
				t.Errorf("Expected body=%s, got %s", expectedBody, *comment.Body)
			}
			return comment, nil, nil
		},
	}

	commenter := comment.NewCommenter(mockClient)
	err := commenter.UpdateComment(context.Background(), "testdev", "hello", "Updated comment", commentID)

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
