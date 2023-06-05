package main

import (
	"log"
	"net/http"

	"github.com/meinantoyuriawan/go-jwt-auth/controller/authcontroller"
	"github.com/meinantoyuriawan/go-jwt-auth/controller/productcontroller"
	"github.com/meinantoyuriawan/go-jwt-auth/middleware"
	"github.com/meinantoyuriawan/go-jwt-auth/models"

	"github.com/gorilla/mux"
)

func main() {
	models.ConnectDB()
	r := mux.NewRouter()

	r.HandleFunc("/login", authcontroller.Login).Methods("POST")
	r.HandleFunc("/register", authcontroller.Register).Methods("POST")
	r.HandleFunc("/logout", authcontroller.Logout).Methods("GET")

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/products", productcontroller.Index).Methods("GET")
	// middleware
	api.Use(middleware.JWTMiddleware)

	log.Fatal(http.ListenAndServe(":8080", r))
}
