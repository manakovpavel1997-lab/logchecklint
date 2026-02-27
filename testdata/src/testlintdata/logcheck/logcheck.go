package logcheck

import "log/slog"

func example() {
	// Rule 1: Uppercase start
	slog.Info("Starting server on port 8080") // want `log message should start with a lowercase letter`
	slog.Error("Failed to connect")           // want `log message should start with a lowercase letter`
	slog.Info("starting server on port 8080") // OK
	slog.Error("failed to connect")           // OK

	// Rule 3: Special characters and emoji
	slog.Info("server started!")       // want `log message should not contain special characters or emoji`
	slog.Warn("something went wrong...") // want `log message should not contain special characters or emoji`
	slog.Info("server started")        // OK
	slog.Warn("something went wrong")  // OK

	// Rule 4: Sensitive data
	slog.Info("user password: 12345")          // want `log message may contain sensitive data`
	slog.Debug("api_key=xyz")                  // want `log message may contain sensitive data`
	slog.Info("token: abc123")                 // want `log message may contain sensitive data`
	slog.Info("user authenticated successfully") // OK
	slog.Debug("api request completed")          // OK
}
