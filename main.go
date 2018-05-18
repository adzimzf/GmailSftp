package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
)

var (
	user = "me"
)

type mailConfig struct {
	EmailFrom    string `json:"email_from"`
	EmailSubject string `json:"email_subject"`
	SFTPhost     string `json:"sftp_host"`
	SFTPPort     string `json:"sftp_port"`
	SftpUser     string `json:"sftp_user"`
	SftpPassword string `json:"sftp_password"`
	SftpPath     string `json:"sftp_path"`
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n\n\n \n%v\n\n\n Then copy here then Hit Enter!\nPaste Here :", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	json.NewEncoder(f).Encode(token)
}

var secret = `
{"installed":{"client_id":"289794109054-kk0njsmecr0shaq9r4bfqd7epon43oqn.apps.googleusercontent.com","project_id":"quixotic-moment-204414","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"0udqc4x3zFPh2YrqVNSS9Kpi","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}
`

func getGmailClient() *gmail.UsersService {
	// b, err := ioutil.ReadFile("client_secret.json")
	// if err != nil {
	// 	log.Fatalf("Unable to read client secret file: %v", err)
	// }

	// If modifying these scopes, delete your previously saved client_secret.json.
	config, err := google.ConfigFromJSON([]byte(secret), gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	srv, err := gmail.New(getClient(config))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}
	return srv.Users
}

var exampleConfig = `
{
        "email_from": "example@gmail.com",
        "email_subject": "EXAMPLE",
        "sftp_host": "127.0.0.1",
        "sftp_port": "22",
        "sftp_user": "user",
        "sftp_password": "secret",
        "sftp_path": "/path/"
}
`

func main() {
	var cfg mailConfig
	cfgByte, err := ioutil.ReadFile("config.json")
	if err != nil {
		err := ioutil.WriteFile("config.json", []byte(exampleConfig), 0644)
		if err != nil {
			log.Fatal("Unable to create config.json")
		}
		fmt.Printf("Please update config.json then run program again \n")
		os.Exit(1)
	}
	err = json.Unmarshal(cfgByte, &cfg)
	if err != nil {
		log.Fatal(err)
	}

	gClient := getGmailClient()
	r, err := gClient.Messages.List(user).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve labels: %v", err)
	}
	if len(r.Messages) == 0 {
		fmt.Println("No labels found.")
		return
	}

	b, fileName, err := cfg.getFile(gClient)
	if err != nil {
		panic(err)
	}

	// write the whole body at once
	err = cfg.sendToSftp(b, fileName)
	if err != nil {
		panic(err)
	}

	fmt.Println("Success upload to ftp")

}

func (cfg mailConfig) getAttachInfo(messages []*gmail.Message, usr *gmail.UsersMessagesService) (string, string, string) {
	for _, l := range messages {
		ms, err := usr.Get(user, l.Id).Do()
		if err != nil {
			log.Println(err)
			return "", "", ""
		}
		if len(ms.Payload.Headers) > 19 {

			if strings.Contains(ms.Payload.Headers[16].Value, cfg.EmailFrom) && strings.Contains(ms.Payload.Headers[19].Value, cfg.EmailSubject) {
				fmt.Printf("from : %s   subject : %s \n", ms.Payload.Headers[16].Value, ms.Payload.Headers[19].Value)
				return l.Id, ms.Payload.Parts[1].Body.AttachmentId, ms.Payload.Parts[1].Filename
			}
		}

	}
	return "", "", ""
}

func (cfg mailConfig) getFile(user *gmail.UsersService) ([]byte, string, error) {
	r, err := user.Messages.List("me").Do()
	if err != nil {
		log.Fatalf("Unable to retrieve labels: %v", err)
	}
	msgID, atthID, fileName := cfg.getAttachInfo(r.Messages, user.Messages)
	if msgID == "" {
		return nil, "", fmt.Errorf("Email you wont not found")
	}

	attach, err := user.Messages.Attachments.Get("me", msgID, atthID).Do()
	if err != nil {
		return nil, "", err
	}
	decoded, err := base64.URLEncoding.DecodeString(attach.Data)
	if err != nil {
		return nil, "", err
	}
	return decoded, fileName, nil
}

func (cfg mailConfig) sendToSftp(file []byte, fileName string) error {
	addr := fmt.Sprintf("%s:%s", cfg.SFTPhost, cfg.SFTPPort)
	config := &ssh.ClientConfig{
		User: cfg.SftpUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(cfg.SftpPassword),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	// Close connection
	defer client.Close()
	path := cfg.SftpPath + fileName
	sftpFile, err := client.OpenFile(path, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return err
	}
	defer sftpFile.Close()
	_, err = sftpFile.Write(file)
	if err != nil {
		return err
	}
	return nil
}
