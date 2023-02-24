package main

import (
	"flag"
	"log"

	"github.com/kirill-scherba/checkemail"
)

func main() {

	// Application flags
	var email string
	flag.StringVar(&email, "e", "", "email address")
	flag.Parse()

	var err error

	// Check email format
	err = checkemail.ValidateEmail(email)
	if err != nil {
		log.Fatalln(err)
	}

	// Check email domain
	err = checkemail.ValidateMX(email)
	if err != nil {
		log.Fatalln(err)
	}

	// Check email smtp
	err = checkemail.ValidateHost(email)
	if err != nil {
		log.Fatalln(err)
	}

	// Validate user
	err = checkemail.ValidateUser("localhost", "info@localhost", email)
	if err != nil {
		log.Fatalln(err)
	}

	// Validated
	log.Println(email, "-> valid email")
}
