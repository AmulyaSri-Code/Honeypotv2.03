package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// DB Configuration
const (
	DBHost     = "localhost"
	DBPort     = 3306
	DBUser     = "root"
	DBPassword = "password"
	DBName     = "honeypot_logs"
)

var db *sql.DB
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Log struct matches the database schema
type Log struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	SourceIP  string    `json:"source_ip"`
}

// Stats struct for dashboard
type Stats struct {
	TotalAttacks int              `json:"total_attacks"`
	ByService    []map[string]any `json:"by_service"`
	TopIPs       []map[string]any `json:"top_ips"`
}

func main() {
	// Connect to Database
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", DBUser, DBPassword, DBHost, DBPort, DBName)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Println("Database connection failed:", err)
	} else {
		log.Println("Connected to database")
	}

	// Router Setup
	r := mux.NewRouter()
	r.HandleFunc("/api/stats", getStats).Methods("GET")
	r.HandleFunc("/api/attacks", getRecentAttacks).Methods("GET")
	r.HandleFunc("/ws/topology", handleTopologyWS)
	r.HandleFunc("/api/falco", handleFalcoWebhook).Methods("POST")

	// CORS Middleware
	r.Use(mux.CORSMethodMiddleware(r))

	srv := &http.Server{
		Handler:      r,
		Addr:         "0.0.0.0:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Go Backend running on port 8000")
	log.Fatal(srv.ListenAndServe())
}

func getStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	stats := Stats{}

	// Total Attacks
	err := db.QueryRow("SELECT COUNT(*) FROM logs").Scan(&stats.TotalAttacks)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// By Service
	rows, err := db.Query("SELECT service, COUNT(*) as count FROM logs GROUP BY service")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var service string
		var count int
		rows.Scan(&service, &count)
		stats.ByService = append(stats.ByService, map[string]any{"service": service, "count": count})
	}

	// Top IPs
	rows, err = db.Query("SELECT source_ip, COUNT(*) as count FROM logs WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY count DESC LIMIT 5")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var count int
		rows.Scan(&ip, &count)
		stats.TopIPs = append(stats.TopIPs, map[string]any{"source_ip": ip, "count": count})
	}

	json.NewEncoder(w).Encode(stats)
}

func getRecentAttacks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	rows, err := db.Query("SELECT id, timestamp, service, level, message, source_ip FROM logs ORDER BY id DESC LIMIT 10")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []Log
	for rows.Next() {
		var l Log
		var sourceIP sql.NullString
		err := rows.Scan(&l.ID, &l.Timestamp, &l.Service, &l.Level, &l.Message, &sourceIP)
		if err != nil {
			continue
		}
		if sourceIP.Valid {
			l.SourceIP = sourceIP.String
		}
		logs = append(logs, l)
	}

	json.NewEncoder(w).Encode(logs)
}

func handleTopologyWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		// Mock topology data for now
		// In real implementation, query DB for recent connections
		topology := map[string]any{
			"nodes": []map[string]any{
				{"id": 1, "label": "Honeypot", "group": "server"},
				{"id": 2, "label": "Attacker 1", "group": "attacker"},
			},
			"edges": []map[string]any{
				{"from": 2, "to": 1},
			},
		}
		c.WriteJSON(topology)
		time.Sleep(5 * time.Second)
	}
}

func handleFalcoWebhook(w http.ResponseWriter, r *http.Request) {
	// Log Falco alert
	log.Println("Received Falco Alert")
	w.WriteHeader(http.StatusOK)
}
