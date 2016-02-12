// htwtxt – hosted twtxt server; see README for copyright and license info

package main

import "bufio"
import "crypto/rand"
import "encoding/base64"
import "errors"
import "flag"
import "fmt"
import "github.com/gorilla/mux"
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

const loginsFile = "logins.txt"
const feedsDir = "feeds"
const ipDelaysFile = "ip_delays.txt"
const pwResetFile = "password_reset.txt"
const legalUrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
	"0123456789_"
const resetLinkExp = 1800

var dataDir string
var feedsPath string
var ipDelaysPath string
var loginsPath string
var mailpassword string
var mailport int
var mailserver string
var mailuser string
var myself string
var pwResetPath string
var signupOpen bool
var templ *template.Template
var templPath string

func createFileIfNotExists(path string) {
	if _, err := os.Stat(path); err != nil {
		file, err := os.Create(path)
		if err != nil {
			log.Fatal("Can't create file: ", err)
		}
		file.Close()
	}
}

func openFile(path string) *os.File {
	file, err := os.Open(path)
	if err != nil {
		file.Close()
		log.Fatal("Can't open file for reading", err)
	}
	return file
}

func linesFromFile(path string) []string {
	text, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Can't read file", err)
	}
	if string(text) == "" {
		return []string{}
	}
	return strings.Split(string(text), "\n")
}

func writeAtomic(path, text string) {
	tmpFile := path + "_tmp"
	if err := ioutil.WriteFile(tmpFile, []byte(text), 0600); err != nil {
		log.Fatal("Trouble writing file", err)
	}
	if err := os.Rename(path, path+"_"); err != nil {
		log.Fatal("Trouble moving file", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		log.Fatal("Trouble moving file", err)
	}
	if err := os.Remove(path + "_"); err != nil {
		log.Fatal("Trouble removing file", err)
	}
}

func writeLinesAtomic(path string, lines []string) {
	writeAtomic(path, strings.Join(lines, "\n"))
}

func appendToFile(path string, msg string) {
	text, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Can't read file", err)
	}
	writeAtomic(path, string(text)+msg+"\n")
}

func removeLineStartingWith(path, token string) {
	lines := linesFromFile(path)
	lineNumber := -1
	for lineCount := 0; lineCount < len(lines); lineCount += 1 {
		line := lines[lineCount]
		tokens := strings.Split(line, " ")
		if 0 == strings.Compare(token, tokens[0]) {
			lineNumber = lineCount
			break
		}
	}
	lines = append(lines[:lineNumber], lines[lineNumber+1:]...)
	writeLinesAtomic(path, lines)
}

func removeLineFromFile(path string, lineNumber int) {
	lines := linesFromFile(ipDelaysPath)
	lines = append(lines[:lineNumber], lines[lineNumber+1:]...)
	writeLinesAtomic(path, lines)
}

func replaceLineStartingWith(path, token, newLine string) {
	lines := linesFromFile(path)
	for i, line := range lines {
		tokens := strings.Split(line, " ")
		if 0 == strings.Compare(token, tokens[0]) {
			lines[i] = newLine
			break
		}
	}
	writeLinesAtomic(path, lines)
}

func tokensFromLine(scanner *bufio.Scanner, nTokensExpected int) []string {
	if !scanner.Scan() {
		return []string{}
	}
	line := scanner.Text()
	tokens := strings.Split(line, " ")
	if len(tokens) != nTokensExpected {
		log.Fatal("Line in file had unexpected number of tokens")
	}
	return tokens
}

func getFromFileEntryFor(path, token string,
	numberTokensExpected int) ([]string, error) {
	file := openFile(path)
	defer file.Close()
	scanner := bufio.NewScanner(bufio.NewReader(file))
	tokens := tokensFromLine(scanner, numberTokensExpected)
	for 0 != len(tokens) {
		if 0 == strings.Compare(tokens[0], token) {
			return tokens[1:], nil
		}
		tokens = tokensFromLine(scanner, 3)
	}
	return []string{}, errors.New("")
}

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
	tokens, err := getFromFileEntryFor(loginsPath, name, 3)
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
		line := ip + " " + strOpenTime + " " + strDelay
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

func accountLine(w http.ResponseWriter, r *http.Request,
	checkDupl bool) (string, error) {
	name := r.FormValue("name")
	pw := r.FormValue("new_password")
	pw2 := r.FormValue("new_password2")
	mail := r.FormValue("mail")
	if 0 != strings.Compare(pw, pw2) || 0 == strings.Compare("name", "") ||
		0 == strings.Compare(pw, "") || !onlyLegalRunes(name) ||
		len(name) > 140 || len(mail) > 140 ||
		strings.ContainsRune(mail, '\n') {
		execTemplate(w, "error.html", "Invalid values.")
		return "", errors.New("")
	}
	if checkDupl {
		_, err := getFromFileEntryFor(loginsPath, name, 3)
		if err == nil {
			execTemplate(w, "error.html", "Username taken.")
			return "", errors.New("")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Can't generate password hash", err)
	}
	return name + " " + string(hash) + " " + mail, nil
}

func prepPasswordReset(name string) {
	if "" == mailserver {
		return
	}
	var target string
	tokens, err := getFromFileEntryFor(loginsPath, name, 3)
	if err != nil {
		return
	} else if "" == tokens[1] {
		return
	}
	target = tokens[1]
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		log.Fatal("Random string generation failed", err)
	}
	urlPart := base64.URLEncoding.EncodeToString(b)
	strTime := strconv.Itoa(int(time.Now().Unix()))
	appendToFile(pwResetPath, urlPart+" "+name+" "+strTime)
	m := gomail.NewMessage()
	m.SetHeader("From", mailuser)
	m.SetHeader("To", target)
	m.SetHeader("Subject", "password reset link")
	msg := myself + "/passwordreset/" + urlPart
	m.SetBody("text/plain", msg)
	d := gomail.NewPlainDialer(mailserver, mailport, mailuser, mailpassword)
	if err := d.DialAndSend(m); err != nil {
		log.Fatal("Can't send mail", err)
	}
}

func cssHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templPath+"/style.css")
}

func passwordResetRequestGetHandler(w http.ResponseWriter, r *http.Request) {
	if "" == mailserver {
		execTemplate(w, "nopwresetrequest.html", "")
	} else {
		execTemplate(w, "pwresetrequest.html", "")
	}
}

func passwordResetRequestPostHandler(w http.ResponseWriter, r *http.Request) {
	go prepPasswordReset(r.FormValue("name"))
	http.Redirect(w, r, "/", 302)
}

func passwordResetLinkGetHandler(w http.ResponseWriter, r *http.Request) {
	urlPart := mux.Vars(r)["secret"]
	if tokens, e := getFromFileEntryFor(pwResetPath, urlPart, 3); e == nil {
		createTime, err := strconv.Atoi(tokens[1])
		if err != nil {
			log.Fatal("Can't read time from pw reset file",
				err)
		}
		if createTime+resetLinkExp >= int(time.Now().Unix()) {
			execTemplate(w, "pwreset.html", urlPart)
			return
		}
	}
	http.Redirect(w, r, "/404", 302)
}

func passwordResetLinkPostHandler(w http.ResponseWriter, r *http.Request) {
	urlPart := mux.Vars(r)["secret"]
	name := r.FormValue("name")
	if tokens, e := getFromFileEntryFor(pwResetPath, urlPart, 3); e == nil {
		createTime, err := strconv.Atoi(tokens[1])
		if err != nil {
			log.Fatal("Can't read time from pw reset file",
				err)
		}
		if tokens[0] == name &&
			createTime+resetLinkExp >= int(time.Now().Unix()) {
			line, err := accountLine(w, r, false)
			if err != nil {
				return
			}
			replaceLineStartingWith(loginsPath, tokens[0], line)
			removeLineStartingWith(pwResetPath, urlPart)
			execTemplate(w, "feedset.html", "")
			return
		}
	}
	http.Redirect(w, r, "/404", 302)
}

func signUpFormHandler(w http.ResponseWriter, r *http.Request) {
	if !signupOpen {
		execTemplate(w, "nosignup.html", "")
		return
	}
	execTemplate(w, "signupform.html", "")
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
	if !signupOpen {
		execTemplate(w, "error.html",
			"Account creation currently not allowed.")
		return
	}
	newLine, err := accountLine(w, r, true)
	if err != nil {
		return
	}
	appendToFile(loginsPath, newLine)
	execTemplate(w, "feedset.html", "")
}

func accountPostHandler(w http.ResponseWriter, r *http.Request) {
	name, err := login(w, r)
	if err != nil {
		return
	}
	newLine, err := accountLine(w, r, false)
	if err != nil {
		return
	}
	replaceLineStartingWith(loginsPath, name, newLine)
	execTemplate(w, "feedset.html", "")
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	file := openFile(loginsPath)
	defer file.Close()
	scanner := bufio.NewScanner(bufio.NewReader(file))
	var dir []string
	tokens := tokensFromLine(scanner, 3)
	for 0 != len(tokens) {
		dir = append(dir, tokens[0])
		tokens = tokensFromLine(scanner, 3)
	}
	type data struct{ Dir []string }
	err := templ.ExecuteTemplate(w, "list.html", data{Dir: dir})
	if err != nil {
		log.Fatal("Trouble executing template", err)
	}
}

func twtxtPostHandler(w http.ResponseWriter, r *http.Request) {
	name, err := login(w, r)
	if err != nil {
		return
	}
	text := r.FormValue("twt")
	twtsFile := feedsPath + "/" + name
	createFileIfNotExists(twtsFile)
	text = strings.Replace(text, "\n", " ", -1)
	appendToFile(twtsFile, time.Now().Format(time.RFC3339)+"\t"+text)
	http.Redirect(w, r, "/"+feedsDir+"/"+name, 302)
}

func twtxtHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !onlyLegalRunes(name) {
		execTemplate(w, "error.html", "Bad path.")
		return
	}
	path := feedsPath + "/" + name
	if _, err := os.Stat(path); err != nil {
		execTemplate(w, "error.html", "Empty twtxt for user.")
		return
	}
	http.ServeFile(w, r, path)
}

func nameMyself(ssl bool, port int) string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal("Can't get local interface addresses", err)
	}
	var ip string
	for _, address := range addresses {
		if ipnet, ok := address.(*net.IPNet); ok &&
			!ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}

		}
	}
	s := ""
	if ssl {
		s = "s"
	}
	return "http" + s + "://" + ip + ":" + strconv.Itoa(port)
}

func readOptions() (*int, *string, *string, *string) {
	portPtr := flag.Int("port", 8000, "port to serve")
	keyPtr := flag.String("key", "", "SSL key file")
	certPtr := flag.String("cert", "", "SSL certificate file")
	flag.StringVar(&templPath, "templates",
		os.Getenv("GOPATH")+"/src/htwtxt/templates",
		"directory where to expect HTML templates")
	flag.StringVar(&dataDir, "dir", os.Getenv("HOME")+"/htwtxt",
		"directory to store feeds and login data")
	contactPtr := flag.String("contact",
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
	if ("" == *keyPtr && "" != *certPtr) ||
		("" != *keyPtr && "" == *certPtr) {
		log.Fatal("Expect either both key and certificate or none.")
	}
	if "" != mailserver {
		fmt.Print("Enter password for smtp server: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Trouble reading password")
		}
		mailpassword = string(bytePassword)
		log.Println(mailpassword)
	}
	return portPtr, keyPtr, certPtr, contactPtr
}

func main() {
	var err error
	portPtr, keyPtr, certPtr, contactPtr := readOptions()
	log.Println("Using as templates dir:", templPath)
	log.Println("Using as data dir:", dataDir)
	loginsPath = dataDir + "/" + loginsFile
	feedsPath = dataDir + "/" + feedsDir
	ipDelaysPath = dataDir + "/" + ipDelaysFile
	pwResetPath = dataDir + "/" + pwResetFile
	if "" != *keyPtr {
		log.Println("Using TLS.")
		if _, err := os.Stat(*certPtr); err != nil {
			log.Fatal("No certificate file found.")
		}
		if _, err := os.Stat(*keyPtr); err != nil {
			log.Fatal("No server key file found.")
		}
	}
	createFileIfNotExists(loginsPath)
	createFileIfNotExists(pwResetPath)
	createFileIfNotExists(ipDelaysPath)
	myself = nameMyself("" != *keyPtr, *portPtr)
	// TODO: Handle err here.
	_ = os.Mkdir(feedsPath, 0700)
	templ, err = template.New("main").ParseGlob(templPath + "/*.html")
	if err != nil {
		log.Fatal("Can't set up new template: ", err)
	}
	router := mux.NewRouter()
	router.HandleFunc("/", handleTemplate("index.html", ""))
	router.HandleFunc("/feeds", listHandler).Methods("GET")
	router.HandleFunc("/feeds/", listHandler)
	router.HandleFunc("/account", handleTemplate("accountform.html", "")).
		Methods("GET")
	router.HandleFunc("/account", accountPostHandler).Methods("POST")
	router.HandleFunc("/signup", signUpFormHandler).Methods("GET")
	router.HandleFunc("/signup", signUpHandler).Methods("POST")
	router.HandleFunc("/feeds", twtxtPostHandler).Methods("POST")
	router.HandleFunc("/feeds/{name}", twtxtHandler)
	router.HandleFunc("/info", handleTemplate("info.html", *contactPtr))
	router.HandleFunc("/passwordreset", passwordResetRequestPostHandler).
		Methods("POST")
	router.HandleFunc("/passwordreset", passwordResetRequestGetHandler).
		Methods("GET")
	router.HandleFunc("/passwordreset/{secret}",
		passwordResetLinkGetHandler).Methods("GET")
	router.HandleFunc("/passwordreset/{secret}",
		passwordResetLinkPostHandler).Methods("POST")
	router.HandleFunc("/style.css", cssHandler)
	http.Handle("/", router)
	log.Println("serving at port", *portPtr)
	if "" != *keyPtr {
		err = http.ListenAndServeTLS(":"+strconv.Itoa(*portPtr),
			*certPtr, *keyPtr, nil)
	} else {
		err = http.ListenAndServe(":"+strconv.Itoa(*portPtr), nil)
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
