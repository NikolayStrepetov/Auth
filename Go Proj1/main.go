package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/signin", SignIn)
	http.HandleFunc("/refresh", Refresh)

	log.Fatal(http.ListenAndServe(":8000", nil))
}
