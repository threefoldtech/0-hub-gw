package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
    "bytes"

	"crypto/ecdsa"
	"github.com/dgrijalva/jwt-go"

	"github.com/tidwall/resp"
    "github.com/gomodule/redigo/redis"
    "github.com/codahale/blake2"
)

var jwtPubKey *ecdsa.PublicKey

type ZdbBackend struct {
    Server redis.Conn
}

type Session struct {
    Authenticated bool
    Username string
    Backend *ZdbBackend
}

type Sessions struct {
    List map[*resp.Conn]*Session
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

//
// list of sessions
//
func NewSessions(backend *ZdbBackend) *Sessions {
    return &Sessions{
        List: make(map[*resp.Conn]*Session),
        Backend: backend,
    }
}

// single session
func (ss *Sessions) NewSession() *Session {
    return &Session{
        Authenticated: false,
        Username: "",
        Backend: ss.Backend,
    }
}

// create a new Session based on a new connection
func (ss *Sessions) SessionAccept(conn *resp.Conn) bool {
    log.Printf("Creating a new session for [%v]\n", conn.RemoteAddr)
    ss.List[conn] = ss.NewSession()
    return true;
}

// verify a jwt token is valid
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
func (ss *Sessions) Authenticate(conn *resp.Conn, args []resp.Value) bool {
    // retreive session from connection
    session := ss.List[conn]
    return session.Authenticate(conn, args)
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
func (ss *Sessions) Info(conn *resp.Conn, args []resp.Value) bool {
    conn.WriteString("Gateway for 0-db (zdb) compatible clients\n")
	return true
}



//
// EXISTS
//
func (ss *Sessions) Exists(conn *resp.Conn, args []resp.Value) bool {
    // retreive session from connection
    session := ss.List[conn]
    return session.Exists(conn, args)
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
func (ss *Sessions) Set(conn *resp.Conn, args []resp.Value) bool {
    // retreive session from connection
    session := ss.List[conn]
    return session.Set(conn, args)
}

func (s *Session) DataValidator(key []byte, payload []byte) bool {
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

    if !s.DataValidator(args[1].Bytes(), args[2].Bytes()) {
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
		log.Println("Closing connections")
        backend.Close()
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
		log.Println("closing kvs")
        backend.Close()
		os.Exit(0)
	}()

	log.Printf("Server listenting on %v\n", *addrflag)
	if err := r.ListenAndServe(*addrflag); err != nil {
		log.Fatal(err)
	}
}
