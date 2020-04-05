package main

import (
	"github.com/gorilla/mux"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
	"html/template"
	"log"
	"net/http"
	"os"
)

var (
	tplIndex *template.Template
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	var err error
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("$PORT must be set")
	}

	tplIndex = template.Must(template.ParseFiles(
		"views/layouts/main.gohtml",
		"views/pages/index.gohtml"))
	if err != nil {
		panic(err)
	}


	r := mux.NewRouter()
	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc(`/{[a-zA-Z0-9=\-\/]+}`, index).Methods("GET")


	// Styles
	assetHandler := http.FileServer(http.Dir("./dist/"))
	assetHandler = http.StripPrefix("/dist/", assetHandler)
	r.PathPrefix("/dist/").Handler(assetHandler)

	log.Printf("Starting server on %s", port)

	http.ListenAndServe(":" + port, r)
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	data := map[string]string {
		"title": "Nice Title",
		"description": "Great description",
		"image": "Image Link",
		"url": "image url",
	}
	if err := tplIndex.Execute(w, data); err != nil {
		panic(err)
	}
}

