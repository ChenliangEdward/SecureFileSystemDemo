package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	PasswordHash  []byte
	SymEncKeyUser []byte              // User's Symmetric Encryption key, used to encrypt the user structure
	PrivKeyMaster userlib.PKEDecKey   // User's Main Private key (decryption)
	PubKeyMaster  userlib.PKEEncKey   // User's Main Public Key (encryption)
	DigiSignSign  userlib.DSSignKey   // User's Digital Signature Signing key (private key)
	DigiSignVeri  userlib.DSVerifyKey // User's Digital Signature Verifying key (public key)
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	userUuid, err := uuid.FromBytes([]byte(username))
	if err != nil {
		return nil, err
	}
	_, check := userlib.DatastoreGet(userUuid)
	if check == true {
		return nil, err
	} // if user exists, abort

	var userdata User
	userdata.Username = username
	userdata.PasswordHash = userlib.Hash([]byte(password))
	userdata.SymEncKeyUser = userlib.Argon2Key([]byte(password), []byte(username), 16)

	userdata.PubKeyMaster.KeyType = "PubKey"
	userdata.PrivKeyMaster.KeyType = "PrivKey"
	userdata.PubKeyMaster, userdata.PrivKeyMaster, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.DigiSignSign, userdata.DigiSignVeri, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userStructPlain, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	userStructEnc := userlib.SymEnc(userdata.SymEncKeyUser, userlib.RandomBytes(16), userStructPlain)
	// This is the struct that goes to the DataStore

	userStructSig, err := userlib.DSSign(userdata.DigiSignSign, userStructEnc)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(userUuid, append(userStructEnc, userStructSig...))
	err = userlib.KeystoreSet(username+"DS", userdata.DigiSignVeri)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"PK", userdata.PubKeyMaster)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userUuid, err := uuid.FromBytes([]byte(username))
	if err != nil {
		return nil, err
	}
	userdataEncSigned, check := userlib.DatastoreGet(userUuid)
	if check == false {
		return nil, err
	}
	digiSignVeri, check := userlib.KeystoreGet(username + "DS") // Get the digital signature verification key
	if check == false {
		return nil, err
	}
	userStructSig := userdataEncSigned[len(userdataEncSigned)-256 : len(userdataEncSigned)] // Get the last 256 bit signature
	userStructEnc := userdataEncSigned[0 : len(userdataEncSigned)-256]                      // Get the Encrypted Data structure part
	err = userlib.DSVerify(digiSignVeri, userStructEnc, userStructSig)

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
