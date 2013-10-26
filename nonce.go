// A nonce is a number or string used only once.
// This is useful for generating a unique token for login pages
// to prevent duplicate or unauthorized submissions.
// @url github.com/LarryBattle/nonce-golang
// @license MIT , 2013
// @author Larry Battle, github.com/LarryBattle
package nonce

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"time"
)

const (
	Version = "0.1.0"
	Token_New  = true
	Token_Used = false
)

// The interface for saving and retrieving data
type IO interface {
	Set(token string, val bool)
	Get(token string) (val bool, has bool)
}

// global IO reader and writer
var db IO

// default IO object
type memory_db struct {
	hash map[string]bool
}

func (m *memory_db) Get(token string) (val bool, has bool) {
	val, has = m.hash[token]
	return
}
func (m *memory_db) Set(token string, val bool) {
	m.hash[token] = val
}

// Set the IO reader and writer
func SetIO(io IO) {
	db = io
}

// Returns a new unique token
func NewToken() string {
	t := createToken()
	for {
		if _, has := db.Get(t); !has {
			break
		}
		t = createToken()
	}
	db.Set(t, Token_New)
	return t
}
func createToken() string {
	h := md5.New()
	now := time.Now().Unix()
	io.WriteString(h, strconv.FormatInt(now, 10))
	io.WriteString(h, strconv.FormatInt(rand.Int63(), 10))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Saves the token as used.
func MarkToken(token string) {
	db.Set(token, Token_Used)
}

// Checks for three conditions.
// 1. If a token is supplied
// 2. If the passed token was created
// 3. If the passed token isn't used'
// An error will be returned if any of the conditions are false
func CheckToken(token string) error {
	if token == "" {
		return errors.New("No token supplied")
	}
	val, has := db.Get(token)
	if !has {
		return errors.New("Unknown token")
	}
	if val == Token_Used {
		return errors.New("Duplicate submission.")
	}
	return nil
}

// Checks if the token is known and new.
// After the check, the token is marked as unused
func CheckThenMarkToken(token string) error {
	if err := CheckToken(token); err != nil {
		return err
	}
	MarkToken(token)
	return nil
}
func init() {
	db = &memory_db{
		make(map[string]bool),
	}
}
