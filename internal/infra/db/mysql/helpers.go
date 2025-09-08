package mysql

import "strings"

// stringOrDash returns "-" when the input is empty/whitespace
func stringOrDash(s string) string {
    if strings.TrimSpace(s) == "" {
        return "-"
    }
    return s
}

