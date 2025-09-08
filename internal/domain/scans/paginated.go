package scans

// PaginatedResult represents a paginated response with data and metadata
type PaginatedResult struct {
	Data       []*Scan `json:"data"`
	Page       int     `json:"page"`
	PageSize   int     `json:"pageSize"`
	Total      int64   `json:"totalItems"`
	TotalPages int     `json:"totalPages"`
}
