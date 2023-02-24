// Copyright 2023 Kirill Scherba <kirill@scherba.ru>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checkemail

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

var (
	ErrInvalidFormat  = errors.New("invalid format")
	ErrDomainRequired = errors.New("domain is required")
)

const smtpTimeout = time.Second * 5

// ValidateEmail validates email address regex
func ValidateEmail(s string) error {
	// if emailRegexp.MatchString(s) {
	// 	return nil
	// }
	// return ErrInvalidFormat
	_, err := mail.ParseAddress(s)
	if err != nil {
		return fmt.Errorf("invalid email address: %s", s)
	}

	return nil
}

// var emailRegexp = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// var emailRegexp = regexp.MustCompile(`(?m)^(((((((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?)|(((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?"((\s? +)?(([!#-[\]-~])|(\\([ -~]|\s))))*(\s? +)?"))?)?(((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?<(((((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?(([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+(\.([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+)*)((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?)|(((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?"((\s? +)?(([!#-[\]-~])|(\\([ -~]|\s))))*(\s? +)?"))@((((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?(([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+(\.([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+)*)((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?)|(((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?\[((\s? +)?([!-Z^-~]))*(\s? +)?\]((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?)))>((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?))|(((((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?(([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+(\.([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+)*)((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?)|(((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?"((\s? +)?(([!#-[\]-~])|(\\([ -~]|\s))))*(\s? +)?"))@((((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?(([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+(\.([A-Za-z0-9!#-'*+\/=?^_\x60{|}~-])+)*)((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?)|(((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?\[((\s? +)?([!-Z^-~]))*(\s? +)?\]((((\s? +)?(\(((\s? +)?(([!-'*-[\]-~]*)|(\\([ -~]|\s))))*(\s? +)?\)))(\s? +)?)|(\s? +))?))))$`)

// ValidateMX validate if MX record exists for a domain
func ValidateMX(email string) error {

	_, domain := splitEmail(email)

	if domain == "" {
		return ErrDomainRequired
	}

	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	if _, err := net.LookupMX(domain); err != nil {
		return fmt.Errorf("mx records in domain %s not found, error: %s", domain, err)
	}

	return nil
}

// ValidateHost validate mail host. This function checks emails hosts mx record 
// and try connect to smtp server with timeout.
func ValidateHost(email string) (err error) {
	_, host := splitEmail(email)

	mx, err := net.LookupMX(host)
	if err != nil {
		return
	}

	client, err := dialTimeout(fmt.Sprintf("%s:%d", mx[0].Host, 25), smtpTimeout)
	if err != nil {
		return err
	}
	client.Close()

	return nil
}

// ValidateUser validate mail host and user.
// If host is valid, requires valid SMTP [1] serverHostName and serverMailAddress to reverse validation
// for prevent SPAN and BOTS.
// [1] https://mxtoolbox.com/SuperTool.aspx
func ValidateUser(serverHostName, serverMailAddress, email string) (err error) {
	_, host := splitEmail(email)

	mx, err := net.LookupMX(host)
	if err != nil {
		return
	}

	client, err := dialTimeout(fmt.Sprintf("%s:%d", mx[0].Host, 25), smtpTimeout)
	if err != nil {
		return err
	}
	defer client.Close()

	err = client.Hello(serverHostName)
	if err != nil {
		return err
	}

	err = client.Mail(serverMailAddress)
	if err != nil {
		return err
	}

	err = client.Rcpt(email)
	if err != nil {
		return err
	}
	return nil
}

// dialTimeout returns a new Client connected to an SMTP server at addr.
// The addr must include a port, as in "mail.example.com:smtp".
func dialTimeout(addr string, timeout time.Duration) (*smtp.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	t := time.AfterFunc(timeout, func() { conn.Close() })
	defer t.Stop()

	host, _, _ := net.SplitHostPort(addr)
	return smtp.NewClient(conn, host)
}

// Split email addresses
func splitEmail(email string) (account, host string) {
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return
	}
	account = email[:i]
	host = email[i+1:]
	return
}
