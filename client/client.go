package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"bytes"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
	// hex.EncodeToString(...) is useful for converting []byte to string

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

func signAppend(content []byte, key userlib.DSSignKey) (result []byte, err error) {
	result = content
	sig, err := userlib.DSSign(key, content)
	if err != nil {
		userlib.DebugMsg("signAppend !! Cannot sign user content!")
		return nil, err
	}
	result = append(result, sig...)
	return result, nil
}

func detachVerify(content []byte, key userlib.DSVerifyKey) (result []byte, err error) {
	sig := content[len(content)-256:]
	result = content[0 : len(content)-256]
	err = userlib.DSVerify(key, result, sig)
	if err != nil {
		userlib.DebugMsg("detachVerify !! Cannot Verify signature")
		return nil, err
	}
	return result, nil

}

func marshalEncrypt(plaintext interface{}, key []byte) (ciphertext []byte, err error) {
	marshaled, err := json.Marshal(plaintext)
	if err != nil {
		userlib.DebugMsg("marshalEncrypt !! Cannot marshal plaintext!\n")
		return nil, err
	}
	marshaledEnced := userlib.SymEnc(key, userlib.RandomBytes(16), marshaled)
	return marshaledEnced, nil
}

func decryptUnmarshal(ciphertext []byte, key []byte) (plaintext FileMeta, err error) {
	marshaled := userlib.SymDec(key, ciphertext)
	err = json.Unmarshal(marshaled, &plaintext)
	if err != nil {
		userlib.DebugMsg("decryptUnmarshal !! Cannot unmarshal\n")
		return FileMeta{}, err
	}
	return plaintext, nil
}

func encSignUploadFile(content []byte) (fileUUID uuid.UUID, symKey []byte, err error) {
	fileUUID = uuid.New()
	// Encrypt Files
	symKey = userlib.RandomBytes(16) // Generate Symmetric encrytion key for Files
	contentEnc := userlib.SymEnc(symKey, userlib.RandomBytes(16), content)
	// Sign the Files
	sum, err := userlib.HMACEval(symKey, contentEnc)
	contentEncSigned := append(contentEnc, sum...)
	if err != nil {
		userlib.DebugMsg("encSignUploadFile !! Cannot sign content!\n")
		return fileUUID, nil, err
	}
	// upload file to Datastore
	userlib.DatastoreSet(fileUUID, contentEncSigned)
	return fileUUID, symKey, err
}

//func detachVerifyMac(contentEncSigned []byte, symKey []byte) (contentEnc []byte, err error) {
//	sig := contentEncSigned[len(contentEncSigned)-64:]        // get the last 64 bytes
//	contentEnc = contentEncSigned[:len(contentEncSigned)-64] // get the elements except for the last 64 bytes
//	sumVerify, err := userlib.HMACEval(symKey, contentEnc)
//	if err != nil {
//		userlib.DebugMsg("DownloadVeriDecFile !! Cannot HMACEval contentEnc!\n")
//		return nil, err
//	}
//	isEqual := userlib.HMACEqual(sumVerify, sig)
//	if !isEqual {
//		userlib.DebugMsg("DownloadVeriDecFile !! Cannot Verify File Signature!\n")
//		return nil, nil
//	}
//	return contentEnc, nil
//
//}

func DownloadVeriDecFile(fileUUID uuid.UUID, symKey []byte) (content []byte, err error) {
	// download file from DataStore
	contentEncSigned, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		userlib.DebugMsg("Cannot get contentEncSigned from DataStore!\n")
		return nil, nil
	}
	// Verify the Files
	sig := contentEncSigned[len(contentEncSigned)-64:]        // get the last 64 bytes
	contentEnc := contentEncSigned[:len(contentEncSigned)-64] // get the elements except for the last 64 bytes
	sumVerify, err := userlib.HMACEval(symKey, contentEnc)
	if err != nil {
		userlib.DebugMsg("DownloadVeriDecFile !! Cannot HMACEval contentEnc!\n")
		return nil, err
	}
	isEqual := userlib.HMACEqual(sumVerify, sig)
	if !isEqual {
		userlib.DebugMsg("DownloadVeriDecFile !! Cannot Verify File Signature!\n")
		return nil, nil
	}
	content = userlib.SymDec(symKey, contentEnc)
	return content, err
}

func getFileMetaData(filename string, userdata *User) (fileMeta FileMeta, fileMetaUUID uuid.UUID, symKeyMeta []byte, err error) {
	filename = filename + "/" + userdata.Username
	_, ok1 := userdata.Myfiles[filename] // get the uuid for fileMeta Structure
	_, ok2 := userdata.SharedWithMe[filename]
	var pubKeyMaster userlib.PKEEncKey
	var digiSignVeri userlib.DSVerifyKey
	if ok1 && !ok2 {
		fileMetaUUID = userdata.Myfiles[filename]
		pubKeyMaster = userdata.PubKeyMaster
		digiSignVeri = userdata.DigiSignVeri
	} else if ok2 && !ok1 {
		invitationUUID := userdata.SharedWithMe[filename]
		var pubKeyByte []byte
		pubKeyByte, err = json.Marshal(userdata.PubKeyMaster)
		if err != nil {
			userlib.DebugMsg("getFileMetaData !! Cannot Marshal userdata.PubKeyMaster!\n")
			return FileMeta{}, uuid.UUID{}, nil, err
		}
		var invitMarshaledEnc []byte
		invitMarshaledEnc, err = DownloadVeriDecFile(invitationUUID, pubKeyByte) // verify integrity of digital envelop
		if err != nil {
			userlib.DebugMsg("fileMetaUUIDMyfile !! Cannot get DigitalEnvelop!\n")
			return FileMeta{}, uuid.UUID{}, nil, err
		}

		// Decrypt Invitation
		var invitMarshaled []byte
		invitMarshaled, err = userlib.PKEDec(userdata.PrivKeyMaster, invitMarshaledEnc)
		if err != nil {
			userlib.DebugMsg("fileMetaUUIDMyfile !! Cannot Decrypt contentMarshaled!\n")
			return FileMeta{}, uuid.UUID{}, nil, err
		}
		var invitation Invitation
		err = json.Unmarshal(invitMarshaled, &invitation)
		if err != nil {
			userlib.DebugMsg("fileMetaUUIDMyfile !! Cannot unmarshal invitation!\n")
			return FileMeta{}, uuid.UUID{}, nil, err
		}

		// Get invitation data
		fileOwner := invitation.FileOwner
		fileMetaUUID = invitation.FileMetaLocation
		var ok bool
		pubKeyMaster, ok = userlib.KeystoreGet(fileOwner + "PK") // Get owner's public key
		if !ok {
			userlib.DebugMsg("getFileMetaData !! Cannot get Owner Public Key!\n")
			return FileMeta{}, uuid.UUID{}, nil, nil
		}
		digiSignVeri, ok = userlib.KeystoreGet(fileOwner + "DS")
		if !ok {
			userlib.DebugMsg("getFileMetaData !! Cannot Get file owner's DSverifyKey!\n")
			return FileMeta{}, uuid.UUID{}, nil, err
		}

	} else if !ok1 && !ok2 {
		userlib.DebugMsg("getFileMetaData !! Cannot find in either Myfiles or SharedWith me!\n")
		return FileMeta{}, uuid.UUID{}, nil, nil
	} else if ok1 && ok2 {
		userlib.DebugMsg("getFileMetaData !! Same filenames appeared in Myfiles and SharedWith me!\n")
		return FileMeta{}, uuid.UUID{}, nil, nil
	}

	// Get and Verify and Decrypt and Unmarshal fileMeta
	fileMetaEncSigned, ok := userlib.DatastoreGet(fileMetaUUID)
	if !ok {
		userlib.DebugMsg("getFileMetaData !! Cannot get fileMeta\n ")
		return FileMeta{}, uuid.UUID{}, nil, nil
	}

	fileMetaEnc, err := detachVerify(fileMetaEncSigned, digiSignVeri)
	if err != nil {
		userlib.DebugMsg("getFileMetaData !! Cannot detachVerify!\n")
		return FileMeta{}, uuid.UUID{}, nil, err
	}

	fileMetaUUIDMarshaled, err := json.Marshal(fileMetaUUID)
	if err != nil {
		userlib.DebugMsg("getFileMetaData !! Cannot marshal FileMetaUUID!\n")
		return FileMeta{}, uuid.UUID{}, nil, err
	}
	PubKeyMasterMarshaled, err := json.Marshal(pubKeyMaster)
	if err != nil {
		userlib.DebugMsg("getFileMetaData !! Cannot marshal pubKeyMaster!\n")
		return FileMeta{}, uuid.UUID{}, nil, err
	}

	symKeyMeta, err = userlib.HashKDF(PubKeyMasterMarshaled[:16], fileMetaUUIDMarshaled) // calculate symKeyMeta
	if err != nil {
		userlib.DebugMsg("getFileMetaData !! Cannot generate symKeyMeta!\n")
		return FileMeta{}, uuid.UUID{}, nil, err
	}

	fileMeta, err = decryptUnmarshal(fileMetaEnc, symKeyMeta[:16]) // decrypt the fileMeta
	if err != nil {
		userlib.DebugMsg("getFileMetaData !! Cannot decryptUnmarshal FileMetaEnc!\n")
		return FileMeta{}, uuid.UUID{}, nil, err
	}

	return fileMeta, fileMetaUUID, symKeyMeta, nil
}

// User This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	PasswordHash  []byte
	SymEncKeyUser []byte               // User's Symmetric Encryption key, used to encrypt the user structure
	PrivKeyMaster userlib.PKEDecKey    // User's Main Private key (decryption)
	PubKeyMaster  userlib.PKEEncKey    // User's Main Public Key (encryption)
	DigiSignSign  userlib.DSSignKey    // User's Digital Signature Signing key (private key)
	DigiSignVeri  userlib.DSVerifyKey  // User's Digital Signature Verifying key (public key)
	Myfiles       map[string]uuid.UUID // Files that the user created
	SharedWithMe  map[string]uuid.UUID // Files that shared with me
	// You can add other attributes here if you want! But note that in order for attributes to
	// Concatenate e fileHeader to the beginning of the content
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type Invitation struct {
	FileMetaLocation userlib.UUID
	FileOwner        string
}
type FileMeta struct {
	FileArray   []userlib.UUID
	FileEncKey  [][]byte
	Owner       string         // The owner of the File
	Invitations []userlib.UUID // The Tree Structure of the sharing tree
}

type File struct {
	Content []byte // The content of the File
}

// Struct

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//userlib.DebugMsg("InitUser >> Generating uuid from username\n")
	userUuid, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		userlib.DebugMsg("InitUser !! Cannot generate uuid from username\n")
		return nil, err
	}
	//userlib.DebugMsg("InitUser >> checking existing uuid\n")
	_, check := userlib.DatastoreGet(userUuid)
	if check == true {
		userlib.DebugMsg("InitUser !! UUID Exists!\n")
		return nil, err
	} // if user exists, abort

	var userdata User
	//userlib.DebugMsg("InitUser >> Initializng User Structure\n")
	userdata.Username = username
	//userlib.DebugMsg("InitUser >> Hashing user password\n")
	userdata.PasswordHash = userlib.Hash([]byte(password))
	//userlib.DebugMsg("InitUser >> Generating SEK for User Structure\n")
	userdata.SymEncKeyUser = userlib.Argon2Key([]byte(password), []byte(username), 16)

	//userlib.DebugMsg("InitUser >> Generating Master Pub Priv Keypair\n")
	userdata.PubKeyMaster.KeyType = "PubKey"
	userdata.PrivKeyMaster.KeyType = "PrivKey"
	userdata.PubKeyMaster, userdata.PrivKeyMaster, err = userlib.PKEKeyGen()
	if err != nil {
		userlib.DebugMsg("InitUser !! Cannot generate Pub Priv Keypair\n")
		return nil, err
	}
	//userlib.DebugMsg("InitUser >> Generating Digital Signature Keys\n")
	userdata.DigiSignSign, userdata.DigiSignVeri, err = userlib.DSKeyGen()
	if err != nil {
		userlib.DebugMsg("InitUser !! Cannot generate Digital Signature Keypairs!\n")
		return nil, err
	}

	//userlib.DebugMsg("InitUser >> Initializing Map Structures\n")
	userdata.Myfiles = make(map[string]uuid.UUID)
	userdata.SharedWithMe = make(map[string]uuid.UUID)

	//userlib.DebugMsg("InitUser >> Converting Userdata into Bytes\n")
	userStructPlain, err := json.Marshal(userdata)
	if err != nil {
		userlib.DebugMsg("Init User !! Cannot conver Userdata into Bytes\n")
		return nil, err
	}

	//userlib.DebugMsg("InitUser >> Encrypting user struct with SEK\n")
	userStructEnc := userlib.SymEnc(userdata.SymEncKeyUser, userlib.RandomBytes(16), userStructPlain)
	// This is the struct that goes to the DataStore
	//userlib.DebugMsg("InitUser >> Signing User struct\n")
	userStructSig, err := userlib.DSSign(userdata.DigiSignSign, userStructEnc)
	if err != nil {
		userlib.DebugMsg("InitUser !! Signing user struct failed\n")
		return nil, err
	}

	//userlib.DebugMsg("InitUser >> Uploading user Struct to Datastore\n")
	userlib.DatastoreSet(userUuid, append(userStructEnc, userStructSig...))

	//userlib.DebugMsg("InitUser >> Uploading DS keys to Keystore\n")
	err = userlib.KeystoreSet(username+"DS", userdata.DigiSignVeri)
	if err != nil {
		userlib.DebugMsg("InitUser !! Uploading to Keystore Failed!\n")
		return nil, err
	}

	//userlib.DebugMsg("InitUser >> Uploading PK keys to Keystore\n")
	err = userlib.KeystoreSet(username+"PK", userdata.PubKeyMaster)
	if err != nil {
		userlib.DebugMsg("InitUser !! Uploading PK keys to Keystore failed!\n")
		return nil, err
	}

	userlib.DebugMsg("InitUser >> InitUser Execution Complete!\n")
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	//userlib.DebugMsg("GetUser >> Getting UUID from username\n")
	userUuid, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		userlib.DebugMsg("GetUser !! Cannot compute UUID from username\n")
		return nil, err
	}
	//userlib.DebugMsg("GetUser >> Getting Sign&Enc userdata from Datastore\n")
	userdataEncSigned, check := userlib.DatastoreGet(userUuid)
	if check == false {
		userlib.DebugMsg("GetUser !! Cannot get userdata from Datastore!\n")
		return nil, err
	}

	//userlib.DebugMsg("GetUser >> Get the Digital Signature Verification Key from KeyStore\n")
	digiSignVeri, check := userlib.KeystoreGet(username + "DS") // Get the digital signature verification key
	if check == false {
		userlib.DebugMsg("GetUser !! Cannot retrieve user's signature verification key!\n")
		return nil, err
	}
	//userlib.DebugMsg("GetUser >> Splitting the userdata to get Enc and Signature\n")
	userStructSig := userdataEncSigned[len(userdataEncSigned)-256 : len(userdataEncSigned)] // Get the last 256 bit signature
	userStructEnc := userdataEncSigned[0 : len(userdataEncSigned)-256]                      // Get the Encrypted Data structure part

	//userlib.DebugMsg("GetUser >> Verify the user signature\n")
	err = userlib.DSVerify(digiSignVeri, userStructEnc, userStructSig)
	if err != nil {
		userlib.DebugMsg("GetUser !! Signature verification failed\n")
		return nil, err
	}

	// After we verify the signature, we decrypt the message
	// get the symmetric enc key from pbkdf first
	symEncKeyUser := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userStruct := userlib.SymDec(symEncKeyUser, userStructEnc)
	err = json.Unmarshal(userStruct, &userdata) // Get userStructure from the
	if err != nil {
		userlib.DebugMsg("GetUser !! Cannot Unmarshal userStruct\n")
		return nil, err
	}

	if bytes.Compare(userlib.Hash([]byte(password)), userdata.PasswordHash) != 0 {
		userlib.DebugMsg("GetUser !! Password isn't matching!\n")
		return nil, err
	}

	userdataptr = &userdata
	userlib.DebugMsg("GetUser >> GetUser Execution Successful <<\n")
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Check if the User has already had the file
	filename = filename + "/" + userdata.Username
	_, ok := userdata.Myfiles[filename]
	// TODO: File overwrite logic here
	if ok {
		return
	}
	_, ok = userdata.SharedWithMe[filename]
	if ok {
		return
	}

	fileUUID, symKey, err := encSignUploadFile(content)
	if err != nil {
		userlib.DebugMsg("StoreFile !! Cannot Upload file to Datastore!\n")
		return err
	}
	//userlib.DebugMsg("StoreFile >> Create File Metadata\n")
	// Create File Metadata
	var newFileMeta FileMeta

	newFileMeta.FileArray = append(newFileMeta.FileArray, fileUUID)
	newFileMeta.FileEncKey = append(newFileMeta.FileEncKey, symKey)
	newFileMeta.Owner = userdata.Username

	// upload metadata
	metaUUID := uuid.New()
	pubkeyMarshaled, err := json.Marshal(userdata.PubKeyMaster)
	if err != nil {
		userlib.DebugMsg("StoreFile !! Cannot json.Marshal userdata.PubkeyMaster\n")
		return err
	}
	metaUUIDMarshaled, err := json.Marshal(metaUUID)
	if err != nil {
		userlib.DebugMsg("StoreFile !! Cannot json.Marshal metaUUID\n")
		return err
	}
	symKeyMeta, err := userlib.HashKDF(pubkeyMarshaled[:16], metaUUIDMarshaled) // Generate Symmetric Key for Filemetas
	if err != nil {
		userlib.DebugMsg("StoreFile !! Cannot generate metaUUID\n")
		return err
	}
	// marshal then encrypt
	newFileMetaEnc, err := marshalEncrypt(newFileMeta, symKeyMeta[:16])
	if err != nil {
		userlib.DebugMsg("Store File !! Cannot Marshal then Encrypt!\n")
		return err
	}
	newFileMetaEncSigned, err := signAppend(newFileMetaEnc, userdata.DigiSignSign)
	if err != nil {
		userlib.DebugMsg("Store File !! Cannot sign NewFileMetaEnc!\n")
		return err
	}
	userlib.DatastoreSet(metaUUID, newFileMetaEncSigned)

	// Update the userdata
	//userlib.DebugMsg("StoreFile >> Update Userdata\n")
	userdata.Myfiles[filename] = metaUUID
	newUserdataByteEnc, err := marshalEncrypt(userdata, userdata.SymEncKeyUser)
	if err != nil {
		userlib.DebugMsg("Store File !! Cannot marshalEncrypt newUserdataByteEnc!\n")
		return err
	}
	uuidCalc, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		userlib.DebugMsg("!! Cannot calculate UUID!\n")
		return err
	}
	newUserdataBytesEncSigned, err := signAppend(newUserdataByteEnc, userdata.DigiSignSign)
	if err != nil {
		userlib.DebugMsg("StoreFile !! Cannot sign newUserByte\n")
		return err
	}
	userlib.DatastoreSet(uuidCalc, newUserdataBytesEncSigned)

	userlib.DebugMsg("StoreFile >> StoreFile Execution Complete <<\n")
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	fileMeta, fileMetaUUID, symKeyMeta, err := getFileMetaData(filename, userdata)
	if err != nil {
		userlib.DebugMsg("AppendToFile !! Cannot Get FileMeta!\n")
		return err
	}

	// Create new file to DataStore
	//userlib.DebugMsg("AppendToFile >> Create new file to DataStore\n")
	fileUUID, symKey, err := encSignUploadFile(content)
	if err != nil {
		userlib.DebugMsg("AppendToFile !! Cannot upload file to Datastore!\n")
		return err
	}

	// Adding file data to fileMeta
	fileMeta.FileEncKey = append(fileMeta.FileEncKey, symKey)
	fileMeta.FileArray = append(fileMeta.FileArray, fileUUID)

	// Encrypt, Sign and Upload the fileMeta
	newFileMetaEnc, err := marshalEncrypt(fileMeta, symKeyMeta[:16])
	if err != nil {
		userlib.DebugMsg("AppendToFile !! Cannot marshalEncrypt fileMeta!\n")
		return err
	}
	newFileMetaEncSigned, err := signAppend(newFileMetaEnc, userdata.DigiSignSign)
	if err != nil {
		userlib.DebugMsg("AppendToFile !! Cannot signAppend newFileMetaEnc!\n")
		return err
	}
	userlib.DatastoreSet(fileMetaUUID, newFileMetaEncSigned)

	userlib.DebugMsg("AppendToFile >> Execution Complete <<")
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	fileMeta, _, _, err := getFileMetaData(filename, userdata)
	if err != nil {
		userlib.DebugMsg("AppendToFile !! Cannot Get FileMeta!\n")
		return nil, err
	}
	for idx, fileUUID := range fileMeta.FileArray {
		symKey := fileMeta.FileEncKey[idx]
		contentSegment, err := DownloadVeriDecFile(fileUUID, symKey)
		if err != nil {
			userlib.DebugMsg("LoadFile !! DownloadVeriDecFile failed!\n")
			return nil, err
		}
		content = append(content, contentSegment...)
	}
	userlib.DebugMsg("LoadFile >> Execution Complete <<")
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//// Determine if the file belongs to me.
	//fileMeta, metaUUID, symKeyMeta, err := getFileMetaData(filename, userdata)
	//if !ok {
	//	metaUUID, ok = userdata.SharedWithMe[filename]
	//	if !ok {
	//		userlib.DebugMsg("CreateInvitation !! Cannot get the file to create invitation!\n")
	//		return uuid.UUID{}, err
	//	}
	//	// TODO: Logic for files that shared with me
	//}
	//
	//// Get the fileMeta
	//// Get the recipient PublicKey
	//// EncSignUpload the invitation
	////
	//
	//return
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
