// htwtxt – hosted twtxt server; see README for copyright and license info

package main

import "bufio"
import "errors"
import "flag"
import "github.com/gorilla/mux"
import "golang.org/x/crypto/bcrypt"
import "html/template"
import "io/ioutil"
import "log"
import "net/http"
import "os"
import "strconv"
import "strings"
import "time"

const loginsFile = "logins.txt"
const feedsDir = "feeds"

var dataDir string
var loginsPath string
var feedsPath string
var templPath string
var templ *template.Template
var contactString string
var signupOpen bool

func createFileIfNotExists(path string) {
	if _, err := os.Stat(path); err != nil {
		file, err := os.Create(path)
		if err != nil {
			log.Fatal("Can't create file: ", err)
		}
		file.Close()
	}
}

func appendToFile(path string, msg string) {
	fileWrite, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	defer fileWrite.Close()
	if err != nil {
		log.Fatal("Can't open file for appending", err)
	}
	if _, err = fileWrite.WriteString(msg); err != nil {
		log.Fatal("Can't write to file", err)
	}
}

func onlyLegalRunes(str string) bool {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
		"0123456789_"
	for _, ru := range str {
		if !(strings.ContainsRune(alphabet, ru)) {
			return false
		}
	}
	return true
}

func execTemplate(w http.ResponseWriter, file string, input string) {
	type data struct{ Msg string }
	err := templ.ExecuteTemplate(w, file, data{Msg: input})
	if err != nil {
		log.Fatal("Trouble executing template", err)
	}
}

func login(w http.ResponseWriter, r *http.Request) (string, error) {
	name := r.FormValue("name")
	pw := r.FormValue("password")
	loginValid := false
	file, err := os.Open(loginsPath)
	defer file.Close()
	if err != nil {
		log.Fatal("Can't open file for reading", err)
	}
	scanner := bufio.NewScanner(bufio.NewReader(file))
	for {
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		tokens := strings.Split(line, " ")
		if len(tokens) == 3 {
			if 0 == strings.Compare(tokens[0], name) &&
				nil == bcrypt.CompareHashAndPassword(
					[]byte(tokens[1]), []byte(pw)) {
				loginValid = true

			}
		}
	}
	if !loginValid {
		execTemplate(w, "error.html", "Bad login.")
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
		len(name) > 140 {
		execTemplate(w, "error.html", "Invalid values.")
		return "", errors.New("")
	}
	if checkDupl {
		fileRead, err := os.Open(loginsPath)
		defer fileRead.Close()
		if err != nil {
			log.Fatal("Can't open file for reading", err)
		}
		scanner := bufio.NewScanner(bufio.NewReader(fileRead))
		for {
			if !scanner.Scan() {
				break
			}
			line := scanner.Text()
			tokens := strings.Split(line, " ")
			if 0 == strings.Compare(name, tokens[0]) {
				execTemplate(w, "error.html", "Username taken.")
				return "", errors.New("")
			}
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Can't generate password hash", err)
	}
	return name + " " + string(hash) + " " + mail, nil
}

func cssHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, templPath+"/style.css")
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	execTemplate(w, "index.html", "")
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	execTemplate(w, "info.html", contactString)
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
	appendToFile(loginsPath, newLine+"\n")
	execTemplate(w, "feedset.html", "")
}

func accountFormHandler(w http.ResponseWriter, r *http.Request) {
	execTemplate(w, "accountform.html", "")
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
	text, err := ioutil.ReadFile(loginsPath)
	if err != nil {
		log.Fatal("Can't read file", err)
	}
	lines := strings.Split(string(text), "\n")
	for i, line := range lines {
		tokens := strings.Split(line, " ")
		if 0 == strings.Compare(name, tokens[0]) {
			lines[i] = newLine
			break
		}
	}
	text = []byte(strings.Join(lines, "\n"))
	tmpFile := loginsPath + "_tmp"
	if err := ioutil.WriteFile(tmpFile, []byte(text), 0600); err != nil {
		log.Fatal("Trouble writing file", err)
	}
	if err := os.Rename(loginsPath, loginsPath+"_"); err != nil {
		log.Fatal("Trouble moving file", err)
	}
	if err := os.Rename(tmpFile, loginsPath); err != nil {
		log.Fatal("Trouble moving file", err)
	}
	if err := os.Remove(loginsPath + "_"); err != nil {
		log.Fatal("Trouble removing file", err)
	}
	execTemplate(w, "feedset.html", "")
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	file, err := os.Open(loginsPath)
	defer file.Close()
	if err != nil {
		log.Fatal("Can't open file for reading", err)
	}
	scanner := bufio.NewScanner(bufio.NewReader(file))
	var dir []string
	for {
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		tokens := strings.Split(line, " ")
		if len(tokens) == 3 {
			dir = append(dir, tokens[0])
		}
	}
	type data struct{ Dir []string }
	err = templ.ExecuteTemplate(w, "list.html", data{Dir: dir})
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
	appendToFile(twtsFile, time.Now().Format(time.RFC3339)+"\t"+text+"\n")
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

func main() {
	var err error
	portPtr := flag.Int("port", 8000, "port to serve")
	keyPtr := flag.String("key", "", "SSL key file")
	certPtr := flag.String("cert", "", "SSL certificate file")
	flag.StringVar(&templPath, "templates",
		os.Getenv("GOPATH")+"/src/htwtxt/templates",
		"directory where to expect HTML templates")
	flag.StringVar(&dataDir, "dir", os.Getenv("HOME")+"/htwtxt",
		"directory to store feeds and login data")
	flag.StringVar(&contactString, "contact",
		"[operator passed no contact info to server]",
		"operator contact info to display on info page")
	flag.BoolVar(&signupOpen, "signup", false,
		"enable on-site account creation")
	flag.Parse()
	log.Println("Using as templates dir:", templPath)
	log.Println("Using as data dir:", dataDir)
	loginsPath = dataDir + "/" + loginsFile
	feedsPath = dataDir + "/" + feedsDir
	if ("" == *keyPtr && "" != *certPtr) ||
		("" != *keyPtr && "" == *certPtr) {
		log.Fatal("Expect either both key and certificate or none.")
	}
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
	// TODO: Handle err here.
	_ = os.Mkdir(feedsPath, 0700)
	templ, err = template.New("main").ParseGlob(templPath + "/*.html")
	if err != nil {
		log.Fatal("Can't set up new template: ", err)
	}
	router := mux.NewRouter()
	router.HandleFunc("/", indexHandler)
	router.HandleFunc("/feeds", listHandler).Methods("GET")
	router.HandleFunc("/feeds/", listHandler)
	router.HandleFunc("/account", accountFormHandler).Methods("GET")
	router.HandleFunc("/account", accountPostHandler).Methods("POST")
	router.HandleFunc("/signup", signUpFormHandler).Methods("GET")
	router.HandleFunc("/signup", signUpHandler).Methods("POST")
	router.HandleFunc("/feeds", twtxtPostHandler).Methods("POST")
	router.HandleFunc("/feeds/{name}", twtxtHandler)
	router.HandleFunc("/feeds/{name}", twtxtHandler)
	router.HandleFunc("/info", infoHandler)
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
