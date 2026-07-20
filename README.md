package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth_chi/v5"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

// IPBlocker manages blocked IPs
type IPBlocker struct {
	blockedIPs map[string]time.Time
	mu         sync.RWMutex
	blockTime  time.Duration // How long an IP stays blocked
}

// NewIPBlocker creates a new IPBlocker
func NewIPBlocker(blockDuration time.Duration) *IPBlocker {
	ib := &IPBlocker{
		blockedIPs: make(map[string]time.Time),
		blockTime:  blockDuration,
	}
	go ib.cleanupLoop() // Start background cleanup
	return ib
}

// BlockIP blocks a given IP address
func (ib *IPBlocker) BlockIP(ip string) {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	ib.blockedIPs[ip] = time.Now().Add(ib.blockTime)
	fmt.Printf("IP Blocked: %s until %s
", ip, ib.blockedIPs[ip].Format(time.RFC3339))
}

// IsBlocked checks if an IP address is currently blocked
func (ib *IPBlocker) IsBlocked(ip string) bool {
	ib.mu.RLock()
	defer ib.mu.RUnlock()
	unblockTime, exists := ib.blockedIPs[ip]
	if !exists {
		return false
	}
	if time.Now().Before(unblockTime) {
		return true
	}
	// If it exists but the time has passed, it's not blocked anymore
	delete(ib.blockedIPs, ip) // Clean it up proactively
	return false
}

// cleanupLoop periodically removes expired blocks
func (ib *IPBlocker) cleanupLoop() {
	ticker := time.NewTicker(ib.blockTime / 2) // Check every half of the block time
	defer ticker.Stop()
	for range ticker.C {
		ib.mu.Lock()
		for ip, unblockTime := range ib.blockedIPs {
			if time.Now().After(unblockTime) {
				delete(ib.blockedIPs, ip)
				fmt.Printf("IP Unblocked: %s
", ip)
			}
		}
		ib.mu.Unlock()
	}
}

// DDoSProtectionMiddleware is a custom middleware for DDoS protection
func DDoSProtectionMiddleware(ipBlocker *IPBlocker, threshold int, banTime time.Duration) func(next http.Handler) http.Handler {
	// Using ulule/limiter for advanced rate limiting
	// 100 requests per minute per IP
	rate, _ := limiter.NewRateFromFormatted("100-M")
	store := memory.NewStore()
	ipLimiter := limiter.New(store, rate)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr // In a production setup, use r.Header.Get("X-Forwarded-For") or similar behind a proxy

			// 1. Check if IP is explicitly blocked
			if ipBlocker.IsBlocked(ip) {
				http.Error(w, "You are blocked due to suspicious activity.", http.StatusForbidden)
				return
			}

			// 2. Apply advanced rate limiting
			context, err := ipLimiter.Get(r.Context(), ip)
			if err != nil {
				// Handle error, e.g., log it and allow the request to pass to avoid blocking legitimate users
				fmt.Fprintf(os.Stderr, "Limiter error: %v
", err)
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}

			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", context.Limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", context.Remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", context.Reset))

			if context.Reached {
				// If rate limit is reached, potentially block the IP for a longer duration
				ipBlocker.BlockIP(ip)
				http.Error(w, "Too many requests. Your IP has been temporarily blocked.", http.StatusTooManyRequests)
				return
			}

			// 3. Simple request count per second (as a secondary check, or if ulule/limiter is not used)
			// This part is more conceptual as ulule/limiter handles it well.
			// For very high-volume attacks, you might have another layer.
			// This is illustrative; in a real scenario, you'd use a more sophisticated library
			// or a dedicated DDoS appliance/service.

			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	r := chi.NewRouter()

	// Initialize IP blocker with a 5-minute block duration
	ipBlocker := NewIPBlocker(5 * time.Minute)

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Tollbooth for basic rate limiting per IP (e.g., 5 requests per second)
	lbr := tollbooth.NewLimiter(5, nil) // 5 requests per second
	r.Use(tollbooth_chi.LimitHandler(lbr))

	// Custom DDoS protection middleware (after tollbooth, as it might block IPs based on accumulated requests)
	// Threshold of 100 requests (per minute from ulule/limiter config) before a ban attempt
	// Ban for 10 minutes if threshold is exceeded
	r.Use(DDoSProtectionMiddleware(ipBlocker, 100, 10*time.Minute))

	// Routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome! This is a protected page."))
	})

	r.Get("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Sensitive API data."))
	})

	fmt.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v
", err)
	}
}

