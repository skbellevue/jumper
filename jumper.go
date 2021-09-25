package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type Route string

const HashRequestRoute = "/hash"
const HashResultRoute = "/hash/([^/]+)"
const StatsRoute = "/stats"

// Wait group for gracefull exit
var wg = &sync.WaitGroup{}

// Our Password structure
type userPassword struct {
	hashedValue string
	completed   bool
}

// Immediate response to hash requests
type HashRequestIdentifier struct {
	Id int `json:"id"`
}

// Hash stats structure
type HashStats struct {
	mutex   sync.Mutex // will guard the singleton
	Total   int64      `json:"total"`
	Average int64      `json:"average"`
}

type HashRequestIndexProvider struct {
	mutex sync.Mutex // will guard `index`
	index int
}

// Global map to cache the hash requests
var hashRequestsCache = make(map[int]*userPassword)
var stats = HashStats{
	Total:   0,
	Average: 0,
}
var indexProvider = HashRequestIndexProvider{index: 0}

func timeTracker(start time.Time, callback func(microseconds int64)) {
	callback(time.Since(start).Microseconds())
}

func (password *userPassword) beginHash(plainPassword string) {
	// track the time for this request
	defer timeTracker(time.Now(), func(microseconds int64) {
		stats.mutex.Lock()
		defer stats.mutex.Unlock()

		current := stats.Average * stats.Total
		current += microseconds

		stats.Total += 1
		stats.Average = current / stats.Total
	})

	timer := time.NewTimer(5 * time.Second)
	<-timer.C

	log.Printf(" -----> Computing hash request")

	hasher := sha512.New()
	hasher.Write([]byte(plainPassword))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	password.hashedValue = sha
	password.completed = true

	log.Printf(" -----> hash is %s", sha)
}

func methodHandler(acceptedMethod string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if acceptedMethod != r.Method {
			w.Header().Set("Allow", acceptedMethod)

			error := fmt.Sprintf("405 Not Allowed: %s only is accepted for this endpoint", acceptedMethod)
			http.Error(w, error, http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func handleHashRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}

	plainPassword := r.FormValue("password")
	indexProvider.mutex.Lock()
	defer indexProvider.mutex.Unlock()
	indexProvider.index++

	currentIndex := indexProvider.index

	pwdEntry := userPassword{}
	hashRequestsCache[currentIndex] = &pwdEntry
	go pwdEntry.beginHash(plainPassword)

	respBody, err := json.Marshal(HashRequestIdentifier{Id: currentIndex})
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}
	// add the location header
	location := fmt.Sprintf("%s/%d", HashRequestRoute, currentIndex)
	w.Header().Set("Location", location)

	// other headers and response status
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(202)
	w.Write(respBody)
}

func getStats(w http.ResponseWriter, r *http.Request) {
	respBody, err := json.Marshal(&stats)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	w.Write(respBody)
}

func getHashedPassword(id int, w http.ResponseWriter) {
	// Lookup request by id
	entry := hashRequestsCache[id]

	// 404 if no entry was found
	if entry == nil {
		w.WriteHeader(404)
		return
	}

	// 202 if the entry is not processed yet
	if !entry.completed {
		// add the location header. Probably unnecessary
		location := fmt.Sprintf("%s/%d", HashRequestRoute, id)
		w.Header().Set("Location", location)
		w.WriteHeader(202)
		return
	}

	w.Header().Set("Content-Type", "application/text")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	w.Write([]byte(entry.hashedValue))
}

func match(path, pattern string, vars ...interface{}) bool {
	regex := regexp.MustCompile("^" + pattern + "$")
	matches := regex.FindStringSubmatch(path)
	if len(matches) <= 0 {
		return false
	}
	for i, match := range matches[1:] {
		switch p := vars[i].(type) {
		case *string:
			*p = match
		case *int:
			n, err := strconv.Atoi(match)
			if err != nil {
				return false
			}
			*p = n
		default:
			panic("Unsupported type")
		}
	}
	return true
}

func server(w http.ResponseWriter, r *http.Request) {
	// Handle graceful exit
	defer wg.Done()
	wg.Add(1)

	var handler http.Handler
	var id int

	p := r.URL.Path

	switch {
	case match(p, HashRequestRoute):
		handler = methodHandler(http.MethodPost, func(rw http.ResponseWriter, r *http.Request) {
			handleHashRequest(rw, r)
		})

	case match(p, HashResultRoute, &id):
		handler = methodHandler(http.MethodGet, func(rw http.ResponseWriter, r *http.Request) {
			getHashedPassword(id, rw)
		})
	case match(p, StatsRoute):
		handler = methodHandler(http.MethodGet, func(rw http.ResponseWriter, r *http.Request) {
			getStats(rw, r)
		})
	default:
		http.NotFound(w, r)
		return
	}

	handler.ServeHTTP(w, r)
}

func main() {
	app := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(server),
	}
	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-termChan
		log.Print("SIGTERM: Shutting down...\n")
		app.Shutdown(context.Background())
	}()

	log.Fatal(app.ListenAndServe())

	log.Println("Waiting for pending requests to complete...")
	wg.Wait()
	log.Println("jobs finished. exiting")
}
