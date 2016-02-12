// htwtxt – hosted twtxt server; see README for copyright and license info

package main

import "errors"
import "flag"
import "fmt"
import "golang.org/x/crypto/bcrypt"
import "golang.org/x/crypto/ssh/terminal"
import "gopkg.in/gomail.v2"
import "html/template"
import "io/ioutil"
import "log"
import "net"
import "net/http"
import "os"
import "strconv"
import "strings"
import "syscall"
import "time"

const resetLinkExp = 1800
const resetWaitTime = 3600 * 24

var contact string
var dialer *gomail.Dialer
var mailuser string
var myself string
var signupOpen bool
var templ *template.Template

func execTemplate(w http.ResponseWriter, file string, input string) {
	type data struct{ Msg string }
	err := templ.ExecuteTemplate(w, file, data{Msg: input})
	if err != nil {
		log.Fatal("Trouble executing template", err)
	}
}

func handleTemplate(path, msg string) func(w http.ResponseWriter,
	r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		execTemplate(w, path, msg)
	}
}

func onlyLegalRunes(str string) bool {
	const legalUrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz0123456789_"
	for _, ru := range str {
		if !(strings.ContainsRune(legalUrlChars, ru)) {
			return false
		}
	}
	return true
}

func checkDelay(w http.ResponseWriter, ip string) (int, error) {
	var err error
	var openTime int
	delay := -1
	if tokens, e := getFromFileEntryFor(ipDelaysPath, ip, 3); e == nil {
		openTime, err = strconv.Atoi(tokens[0])
		if err != nil {
			log.Fatal("Can't parse IP delays file", err)
		}
		delay, err = strconv.Atoi(tokens[1])
		if err != nil {
			log.Fatal("Can't parse IP delays file", err)
		}
		if int(time.Now().Unix()) < openTime {
			execTemplate(w, "error.html",
				"This IP must wait a while for its "+
					"next login attempt.")
			err = errors.New("")
		}
	}
	return delay, err
}

func login(w http.ResponseWriter, r *http.Request) (string, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Fatal("Can't parse ip from request", err)
	}
	delay, err := checkDelay(w, ip)
	if err != nil {
		return "", err
	}
	name := r.FormValue("name")
	pw := r.FormValue("password")
	loginValid := false
	tokens, err := getFromFileEntryFor(loginsPath, name, 5)
	if err == nil && nil == bcrypt.CompareHashAndPassword([]byte(tokens[0]),
		[]byte(pw)) {
		loginValid = true
		if 0 <= delay {
			removeLineStartingWith(ipDelaysPath, ip)
		}
	}
	if !loginValid {
		newLine := delay == -1
		delay = 2 * delay
		if -2 == delay {
			delay = 1
		}
		strOpenTime := strconv.Itoa(int(time.Now().Unix()) + delay)
		strDelay := strconv.Itoa(delay)
		line := ip + "\t" + strOpenTime + "\t" + strDelay
		if newLine {
			appendToFile(ipDelaysPath, line)
		} else {
			replaceLineStartingWith(ipDelaysPath, ip, line)
		}
		execTemplate(w, "error_login.html", "Bad login.")
		return name, errors.New("")
	}
	return name, nil
}

func nameIsLegal(name string) bool {
	return !("" == name || !onlyLegalRunes(name) || len(name) > 140)
}

func passwordIsLegal(password string) bool {
	return !("" == password)
}

func hashFromPw(pw string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Can't generate hash", err)
	}
	return string(hash)
}

func newPassword(w http.ResponseWriter, r *http.Request) (string, error) {
	pw := r.FormValue("new_password")
	pw2 := r.FormValue("new_password2")
	if 0 != strings.Compare(pw, pw2) {
		return "", errors.New("Password values did not match")
	} else if !passwordIsLegal(pw) {
		return "", errors.New("Illegal password.")
	}
	return hashFromPw(pw), nil
}

func newMailAddress(w http.ResponseWriter, r *http.Request) (string, error) {
	mail := r.FormValue("mail")
	if len(mail) > 140 || strings.ContainsRune(mail, '\n') ||
		strings.ContainsRune(mail, '\t') {
		return "", errors.New("Illegal mail address.")
	}
	return mail, nil
}

func newSecurityQuestion(w http.ResponseWriter, r *http.Request) (string,
	string, error) {
	secquestion := r.FormValue("secquestion")
	secanswer := r.FormValue("secanswer")
	if "" == secquestion || len(secquestion) > 140 ||
		strings.ContainsRune(secquestion, '\n') ||
		strings.ContainsRune(secquestion, '\t') {
		return "", "", errors.New("Illegal security question.")
	} else if "" == secanswer {
		return "", "", errors.New("Illegal security question answer.")
	}
	return secquestion, hashFromPw(secanswer), nil
}

func changeLoginField(w http.ResponseWriter, r *http.Request,
	getter func(w http.ResponseWriter, r *http.Request) (string, error),
	position int) {
	name, err := login(w, r)
	if err != nil {
		return
	}
	input, err := getter(w, r)
	if err != nil {
		execTemplate(w, "error.html", err.Error())
		return
	}
	tokens, err := getFromFileEntryFor(loginsPath, name, 5)
	if err != nil {
		log.Fatal("Can't get entry for user", err)
	}
	tokens[position] = input
	replaceLineStartingWith(loginsPath, name,
		name+"\t"+strings.Join(tokens, "\t"))
	execTemplate(w, "feedset.html", "")
}

func nameMyself(ssl bool, port int) string {
	resp, err := http.Get("http://myexternalip.com/raw")
	defer resp.Body.Close()
	if err != nil {
		log.Fatal("Trouble getting IP", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Trouble reading IP message body", err)
	}
	ip := strings.Replace(string(body), "\n", "", -1)
	s := ""
	if ssl {
		s = "s"
	}
	return "http" + s + "://" + ip + ":" + strconv.Itoa(port)
}

func readOptions() (string, int, string, int, string) {
	var mailpw string
	var mailport int
	var mailserver string
	var port int
	var newLogin string
	flag.StringVar(&newLogin, "adduser", "", "instead of starting as "+
		"server, add user with login NAME:PASSWORD")
	flag.IntVar(&port, "port", 8000, "port to serve")
	flag.StringVar(&keyPath, "key", "", "SSL key file")
	flag.StringVar(&certPath, "cert", "", "SSL certificate file")
	flag.StringVar(&templPath, "templates",
		os.Getenv("GOPATH")+"/src/htwtxt/templates",
		"directory where to expect HTML templates")
	flag.StringVar(&dataDir, "dir", os.Getenv("HOME")+"/htwtxt",
		"directory to store feeds and login data")
	flag.StringVar(&contact, "contact",
		"[operator passed no contact info to server]",
		"operator contact info to display on info page")
	flag.BoolVar(&signupOpen, "signup", false,
		"enable on-site account creation")
	flag.StringVar(&mailserver, "mailserver", "",
		"SMTP server to send mails through")
	flag.IntVar(&mailport, "mailport", 0,
		"port of SMTP server to send mails through")
	flag.StringVar(&mailuser, "mailuser", "",
		"username to login with on SMTP server to send mails through")
	flag.Parse()
	if "" != mailserver && ("" == mailuser || 0 == mailport) {
		log.Fatal("Mail server usage needs username and port number")
	}
	if ("" == keyPath && "" != certPath) ||
		("" != keyPath && "" == certPath) {
		log.Fatal("Expect either both key and certificate or none.")
	}
	if "" != mailserver {
		fmt.Print("Enter password for smtp server: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Trouble reading password")
		}
		mailpw = string(bytePassword)
		fmt.Println("")
	}
	return mailserver, mailport, mailpw, port, newLogin
}

func addUser(login string) {
	fields := strings.Split(login, ":")
	if len(fields) != 2 {
		log.Fatal("Malformed adduser string, must be NAME:PASSWORD")
	}
	name := fields[0]
	password := fields[1]
	if !nameIsLegal(name) {
		log.Fatal("Malformed adduser NAME argument.")
	}
	if !passwordIsLegal(password) {
		log.Fatal("Malformed adduser PASSWORD argument.")
	}
	if _, err := getFromFileEntryFor(loginsPath, name, 5); err == nil {
		log.Fatal("Username already taken.")
	}
	hash := hashFromPw(password)
	appendToFile(loginsPath, name+"\t"+hash+"\t\t\t")
	fmt.Println("Added user.")
}

func main() {
	var err error
	mailserver, mailport, mailpw, port, newLogin := readOptions()
	initFilesAndDirs()
	if "" != newLogin {
		addUser(newLogin)
		return
	}
	myself = nameMyself("" != keyPath, port)
	templ, err = template.New("main").ParseGlob(templPath + "/*.html")
	if err != nil {
		log.Fatal("Can't set up new template: ", err)
	}
	http.Handle("/", handleRoutes())
	dialer = gomail.NewPlainDialer(mailserver, mailport, mailuser, mailpw)
	log.Println("serving at port", port)
	if "" != keyPath {
		err = http.ListenAndServeTLS(":"+strconv.Itoa(port),
			certPath, keyPath, nil)
	} else {
		err = http.ListenAndServe(":"+strconv.Itoa(port), nil)
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
