package main
import (
	"fmt"
	"log"
	"os"
	"time"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"net"
	"flag"
)
func connect(user, password, host string, port int) (*ssh.Session, error) {
	type HostKeyCallback func(hostname string, remote net.Addr, key ssh.PublicKey) error
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		session      *ssh.Session
		err          error
	)
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))
	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	addr = fmt.Sprintf("%s:%d", host, port)
	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}
	return session, nil
}
func main() {
	host := flag.String("host", "", "ip address")
	port := flag.Int("port", 22, "ssh port")
	user := flag.String("u", "root", "username")
	passwd := flag.String("p", "", "password")
	cmd := flag.String("c", "whoami", "commond")
	flag.Parse()
	session, err := connect(*user, *passwd, *host, *port)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(fd, oldState)
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		panic(err)
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		log.Fatal(err)
	}
	session.Run(*cmd)
}