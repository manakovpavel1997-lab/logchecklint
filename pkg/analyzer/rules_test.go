package analyzer

import "testing"

func TestCheckLowercaseStart(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"lowercase start", "starting server", false},
		{"uppercase start", "Starting server", true},
		{"empty string", "", false},
		{"number start", "123 items processed", false},
		{"lowercase single char", "a", false},
		{"uppercase single char", "A", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckLowercaseStart(tt.msg)
			if got != tt.wantErr {
				t.Errorf("CheckLowercaseStart(%q) = %v, want %v", tt.msg, got, tt.wantErr)
			}
		})
	}
}

func TestCheckEnglishOnly(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"english only", "starting server", false},
		{"russian text", "запуск сервера", true},
		{"mixed languages", "server запуск", true},
		{"chinese text", "服务器启动", true},
		{"empty string", "", false},
		{"with numbers", "port 8080 started", false},
		{"with allowed punctuation", "connection: ok", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckEnglishOnly(tt.msg)
			if got != tt.wantErr {
				t.Errorf("CheckEnglishOnly(%q) = %v, want %v", tt.msg, got, tt.wantErr)
			}
		})
	}
}

func TestCheckSpecialCharsOrEmoji(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"clean message", "server started", false},
		{"with exclamation", "server started!", true},
		{"with emoji rocket", "server started\U0001F680", true},
		{"with multiple exclamations", "connection failed!!!", true},
		{"with ellipsis", "something went wrong...", true},
		{"with tilde", "~approximate value", true},
		{"with hash", "#channel created", true},
		{"empty string", "", false},
		{"with colon", "server: started", false},
		{"with hyphen", "re-connection attempt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSpecialCharsOrEmoji(tt.msg)
			if got != tt.wantErr {
				t.Errorf("CheckSpecialCharsOrEmoji(%q) = %v, want %v", tt.msg, got, tt.wantErr)
			}
		})
	}
}

func TestCheckSensitiveData(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"clean message", "user authenticated successfully", false},
		{"contains password", "user password: 12345", true},
		{"contains token", "token: abc123", true},
		{"contains api_key", "api_key=xyz", true},
		{"contains secret", "secret value logged", true},
		{"contains credential", "credential check passed", true},
		{"case insensitive", "PASSWORD reset", true},
		{"contains apikey", "apikey sent", true},
		{"empty string", "", false},
		{"safe message", "request completed in 200ms", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSensitiveData(tt.msg)
			if got != tt.wantErr {
				t.Errorf("CheckSensitiveData(%q) = %v, want %v", tt.msg, got, tt.wantErr)
			}
		})
	}
}

func TestCheckSensitiveDataWithCustomKeywords(t *testing.T) {
	custom := []string{"ssn_number", "bank_account"}

	tests := []struct {
		name    string
		msg     string
		wantErr bool
	}{
		{"default keyword", "password leaked", true},
		{"custom keyword", "ssn_number: 123", true},
		{"another custom", "bank_account logged", true},
		{"clean message", "operation completed", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSensitiveDataWithCustomKeywords(tt.msg, custom)
			if got != tt.wantErr {
				t.Errorf("CheckSensitiveDataWithCustomKeywords(%q) = %v, want %v", tt.msg, got, tt.wantErr)
			}
		})
	}
}
