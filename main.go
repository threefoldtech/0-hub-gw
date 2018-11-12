package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"crypto/ecdsa"
	"github.com/dgrijalva/jwt-go"

	"github.com/codahale/blake2"
	"github.com/gomodule/redigo/redis"
	"github.com/tidwall/resp"
)

var jwtPubKey *ecdsa.PublicKey

type ZdbBackend struct {
	Server redis.Conn
}

type Session struct {
	Authenticated bool
	Username      string
	Backend       *ZdbBackend
}

type Sessions struct {
	List    map[*resp.Conn]*Session
	Backend *ZdbBackend
}

//
// its you online
//
const (
	iyoPubKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAES5X8XrfKdx9gYayFITc89wad4usrk0n2
7MjiGYvqalizeSWTHEpnd7oea9IQ8T5oJjMVH5cc0H5tFSKilFFeh//wngxIyny6
6+Vq5t5B0V0Ehy01+2ceEon2Y0XDkIKv
-----END PUBLIC KEY-----`
)

func cryptoInit() {
	var err error

	jwtPubKey, err = jwt.ParseECPublicKeyFromPEM([]byte(iyoPubKey))
	if err != nil {
		log.Panicf("failed to parse pub key:%v\n", err)
	}
}

// NewSessions create a new object containing
// list of sessions which can be mapped to connections
func NewSessions(backend *ZdbBackend) *Sessions {
	return &Sessions{
		List:    make(map[*resp.Conn]*Session),
		Backend: backend,
	}
}

// NewSession create a single session object
// used to keep track of a user connection session
// (basically if the user is connected and it's username)
func (ss *Sessions) NewSession() *Session {
	return &Session{
		Authenticated: false,
		Username:      "",
		Backend:       ss.Backend,
	}
}

// SessionAccept allocate a new object to map it with the connection
// associated with the client
func (ss *Sessions) SessionAccept(conn *resp.Conn) bool {
	log.Printf("Creating a new session for [%v]\n", conn.RemoteAddr)
	ss.List[conn] = ss.NewSession()
	return true
}

// verifyToken ensure the jwt token received comes from ItsYouOnline
// and is still valid
func verifyToken(tokenStr string) (bool, string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodES384 {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtPubKey, nil
	})

	if err != nil {
		return false, "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Printf("Token validated: %v", claims["username"])
		return true, claims["username"].(string), nil
	}

	return false, "", nil
}

//
// AUTH
//
// Authenticate handle AUTH redis command
// this takes the jwt token as single argument
func (ss *Sessions) Authenticate(conn *resp.Conn, args []resp.Value) bool {
	if session, ok := ss.List[conn]; ok {
		return session.Authenticate(conn, args)
	}

	// connection not found, closing
	return false
}

func (s *Session) Authenticate(conn *resp.Conn, args []resp.Value) bool {
	if len(args) != 2 {
		conn.WriteError(errors.New("Wrong number of arguments for 'AUTH' command"))
		return true
	}

	valid, username, err := verifyToken(args[1].String())
	if !valid {
		log.Printf("Authentication failed: %v\n", err)
		conn.WriteError(errors.New("Access denied"))

		s.Authenticated = false
		return true
	}

	s.Username = username
	s.Authenticated = true

	conn.WriteSimpleString("OK - " + s.Username)
	return true
}

//
// INFO
//
// Info is used to retreive information about the server, we don't
// forward the raw response from 0-db, we fake the reply, but still
// match "0-db" on the reply, some project (like 0-flist) rely on
// thet to choose the API to use
func (ss *Sessions) Info(conn *resp.Conn, args []resp.Value) bool {
	conn.WriteString("Gateway for 0-db (zdb) compatible clients\n")
	return true
}

//
// EXISTS
//
// Exists forward the EXISTS command to 0-db, returns 1 or 0 as integer
// if the given key exists or not
func (ss *Sessions) Exists(conn *resp.Conn, args []resp.Value) bool {
	if session, ok := ss.List[conn]; ok {
		return session.Exists(conn, args)
	}

	// connection not found, closing
	return false
}

func (s *Session) Exists(conn *resp.Conn, args []resp.Value) bool {
	if !s.Authenticated {
		log.Printf("Command EXISTS for unauthenticated user [%v]\n", conn.RemoteAddr)
		conn.WriteError(errors.New("Permission denied"))
		return true
	}

	if len(args) != 2 {
		conn.WriteError(errors.New("Wrong number of arguments for 'EXISTS' command"))
		return true
	}

	reply, err := s.Backend.Server.Do("EXISTS", args[1])
	if err != nil {
		log.Printf("Exists failed: %v\n", err)
		conn.WriteError(errors.New("Cannot perform query right now"))
		return true
	}

	// forward value
	conn.WriteInteger(int(reply.(int64)))

	return true
}

//
// SET
//
// Set does a simple forward to 0-db, but in addition, it ensure
// the payload and the key are well related (the key should be
// the hash of the payload, that's what's intended to be in the
// database of the hub), if the check doesn't match, the Set is
// dropped
func (ss *Sessions) Set(conn *resp.Conn, args []resp.Value) bool {
	// retreive session from connection
	if session, ok := ss.List[conn]; ok {
		return session.Set(conn, args)
	}

	// connection not found, closing
	return false
}

// DataValidator computes the blake2 hash of the payload
// and check if the key provided is the same
func DataValidator(key []byte, payload []byte) bool {
	h := blake2.New(&blake2.Config{Size: 16})
	h.Write(payload)
	d := h.Sum(nil)

	return (bytes.Compare(d, key) == 0)
}

func (s *Session) Set(conn *resp.Conn, args []resp.Value) bool {
	if !s.Authenticated {
		log.Printf("Command SET for unauthenticated user [%v]\n", conn.RemoteAddr)
		conn.WriteError(errors.New("Permission denied"))
		return true
	}

	if len(args) != 3 {
		conn.WriteError(errors.New("Wrong number of arguments for 'SET' command"))
		return true
	}

	if !DataValidator(args[1].Bytes(), args[2].Bytes()) {
		log.Printf("Validator failed, payload hash doesn't match key\n")
		conn.WriteError(errors.New("Unauthorized payload"))
		return true
	}

	reply, err := s.Backend.Server.Do("SET", args[1], args[2])
	if err != nil {
		log.Printf("SET failed: %v\n", err)
		conn.WriteError(errors.New("Cannot perform query right now"))
		return true
	}

	// reply can be nul or key name
	// checking type and forwarding according type
	if reply == nil {
		conn.WriteNull()
		return true
	}

	value, ok := reply.([]uint8)
	if ok {
		conn.WriteBytes(value)
		return true
	}

	// zdb replied something weird
	log.Printf("Unexpected response: %v\n", reply)
	conn.WriteError(errors.New("Unexpected response from server"))

	return true
}

//
// backend
//
// NewBackend creates a backend object, which is a
// connection to 0-db
func NewBackend(server string) *ZdbBackend {
	c, err := redis.Dial("tcp", server)
	if err != nil {
		log.Fatal(err)
	}

	return &ZdbBackend{
		Server: c,
	}
}

func (b *ZdbBackend) Close() {
	b.Server.Close()
}

func Cleanup(backend *ZdbBackend) {
	log.Println("Closing backend")
	backend.Close()
}

var addrflag = flag.String("addr", ":16379", "listening address")
var backendflag = flag.String("backend", "127.0.0.1:9900", "zdb backend host/port")

func main() {
	flag.Parse()
	cryptoInit()

	backend := NewBackend(*backendflag)
	ss := NewSessions(backend)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT)

	defer func() {
		Cleanup(backend)
		os.Exit(0)
	}()

	r := resp.NewServer()
	r.AcceptFunc(ss.SessionAccept)
	r.HandleFunc("auth", ss.Authenticate)
	r.HandleFunc("exists", ss.Exists)
	r.HandleFunc("set", ss.Set)
	r.HandleFunc("info", ss.Info)

	go func() {
		<-c
		Cleanup(backend)
		os.Exit(0)
	}()

	log.Printf("Server listenting on %v\n", *addrflag)
	if err := r.ListenAndServe(*addrflag); err != nil {
		log.Fatal(err)
	}
}
