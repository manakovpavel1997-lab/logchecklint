package analyzer

import (
	"strings"
	"unicode"
)

// sensitiveKeywords содержит только очевидно чувствительные слова.
var sensitiveKeywords = []string{
	"password", "passwd", "pwd",
	"token", "access_token", "refresh_token",
	"api_key", "apikey", "api-key",
	"secret", "secret_key",
	"credential", "credentials",
	"private_key", "privatekey",
	"ssn", "social_security",
	"credit_card", "creditcard",
	"cvv", "pin",
}

// CheckLowercaseStart проверяет, что сообщение начинается со строчной буквы.
// true = правило нарушено (первая буква заглавная).
func CheckLowercaseStart(msg string) bool {
	if msg == "" {
		return false
	}
	r := rune(msg[0])
	return unicode.IsUpper(r)
}

// CheckEnglishOnly проверяет, что в сообщении только ASCII-символы.
// true = правило нарушено (есть неанглийские символы).
func CheckEnglishOnly(msg string) bool {
	for _, r := range msg {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// символы, которые нельзя использовать в логах
const specialChars = "!@#$%^&*~`<>{}|\\"

// CheckSpecialCharsOrEmoji проверяет спецсимволы и эмодзи.
// true = правило нарушено.
func CheckSpecialCharsOrEmoji(msg string) bool {
	for _, r := range msg {
		if isEmoji(r) {
			return true
		}
		if strings.ContainsRune(specialChars, r) {
			return true
		}
	}
	// повторяющаяся пунктуация
	if strings.Contains(msg, "!!") || strings.Contains(msg, "??") ||
		strings.Contains(msg, "...") {
		return true
	}
	return false
}

// isEmoji проверяет, является ли руна эмодзи.
func isEmoji(r rune) bool {
	return (r >= 0x1F600 && r <= 0x1F64F) || // Emoticons
		(r >= 0x1F300 && r <= 0x1F5FF) || // Misc Symbols and Pictographs
		(r >= 0x1F680 && r <= 0x1F6FF) || // Transport and Map
		(r >= 0x1F1E0 && r <= 0x1F1FF) || // Flags
		(r >= 0x2600 && r <= 0x26FF) || // Misc symbols
		(r >= 0x2700 && r <= 0x27BF) || // Dingbats
		(r >= 0xFE00 && r <= 0xFE0F) || // Variation Selectors
		(r >= 0x1F900 && r <= 0x1F9FF) || // Supplemental Symbols
		(r >= 0x1FA00 && r <= 0x1FA6F) || // Chess Symbols
		(r >= 0x1FA70 && r <= 0x1FAFF) || // Symbols Extended-A
		(r >= 0x200D && r <= 0x200D) || // Zero Width Joiner
		(r >= 0x231A && r <= 0x231B) || // Watch, Hourglass
		(r >= 0x23E9 && r <= 0x23F3) || // Various symbols
		(r >= 0x2934 && r <= 0x2935) || // Arrows
		(r >= 0x25AA && r <= 0x25AB) || // Squares
		(r >= 0x25B6 && r <= 0x25C0) || // Triangles
		(r >= 0x25FB && r <= 0x25FE) || // Squares
		(r >= 0x2614 && r <= 0x2615) || // Umbrella, Hot Beverage
		(r >= 0x2648 && r <= 0x2653) || // Zodiac
		(r >= 0x267F && r <= 0x267F) || // Wheelchair
		(r >= 0x2702 && r <= 0x27B0) || // Dingbats
		(r >= 0x1F004 && r <= 0x1F004) || // Mahjong
		(r >= 0x1F0CF && r <= 0x1F0CF) // Joker
}

// CheckSensitiveData проверяет наличие чувствительных данных.
// true = правило нарушено.
func CheckSensitiveData(msg string) bool {
	lower := strings.ToLower(msg)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

// CheckSensitiveDataWithCustomKeywords добавляет пользовательские ключевые слова.
func CheckSensitiveDataWithCustomKeywords(msg string, customKeywords []string) bool {
	if CheckSensitiveData(msg) {
		return true
	}
	lower := strings.ToLower(msg)
	for _, keyword := range customKeywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}
