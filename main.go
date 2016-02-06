package main

import "bufio"
import "errors"
import "github.com/gorilla/sessions"
import "github.com/gorilla/mux"
import "golang.org/x/crypto/bcrypt"
import "html/template"
import "log"
import "net/http"
import "os"
import "strconv"
import "strings"
import "time"

const loginsFile = "logins.txt"
const twtsDir = "twtxt"
const portDefault = 8000

var useHttps bool
var templ *template.Template
var store *sessions.CookieStore

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

func getUserFromSession(r *http.Request) (string, error) {
	if session, err := store.Get(r, "session"); err == nil {
		if str, ok := session.Values["name"].(string); ok {
			return str, nil
		}
	}
	return "", errors.New("no valid session")
}

func execTemplate(w http.ResponseWriter, file string, input string) {
	type data struct{ Msg string }
	err := templ.ExecuteTemplate(w, file, data{Msg: input})
	if err != nil {
		log.Fatal("Trouble executing template", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromSession(r)
	if err != nil {
		execTemplate(w, "loginform.html", "")
		return
	}
	execTemplate(w, "twtxt.html", user)
}

func logInPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	pw := r.FormValue("password")
	file, err := os.Open(loginsFile)
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
		if len(tokens) == 2 {
			if 0 == strings.Compare(tokens[0], name) &&
				nil == bcrypt.CompareHashAndPassword(
					[]byte(tokens[1]), []byte(pw)) {
				// TODO: Handle err here.
				session, _ := store.Get(r, "session")
				if useHttps {
					session.Options.Secure = true
				}
				session.Options.HttpOnly = true
				session.Values["name"] = tokens[0]
				if err := session.Save(r, w); err != nil {
					log.Fatal("session save trouble:", err)
				}
				http.Redirect(w, r, "/", 302)
				return
			}
		}
	}
	execTemplate(w, "bad.html", "Bad login.")
}

func logOutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		log.Fatal("session get trouble", err)
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		log.Fatal("session save trouble", err)
	}
	http.Redirect(w, r, "/", 302)
}

func signUpFormHandler(w http.ResponseWriter, r *http.Request) {
	execTemplate(w, "signupform.html", "")
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	pw := r.FormValue("password")
	if 0 == strings.Compare("name", "") || 0 == strings.Compare(pw, "") ||
		!onlyLegalRunes(name) {
		execTemplate(w, "bad.html", "Invalid values.")
		return
	}
	fileRead, err := os.Open(loginsFile)
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
			execTemplate(w, "bad.html", "Username taken.")
			return
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Can't generate password hash", err)
	}
	new_line := name + " " + string(hash) + "\n"
	appendToFile(loginsFile, new_line)
	execTemplate(w, "signup.html", "")
}

func twtPostHandler(w http.ResponseWriter, r *http.Request) {
	text := r.FormValue("twt")
	user, err := getUserFromSession(r)
	if err != nil {
		execTemplate(w, "bad.html", "Invalid session.")
		return
	}
	twtsFile := twtsDir + "/" + user
	createFileIfNotExists(twtsFile)
	text = strings.Replace(text, "\n", " ", -1)
	appendToFile(twtsFile, time.Now().Format(time.RFC3339)+"\t"+text+"\n")
	http.Redirect(w, r, "/"+twtsFile, 302)
}

func twtxtHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if !onlyLegalRunes(name) {
		execTemplate(w, "bad.html", "Bad path.")
		return
	}
	path := twtsDir + "/" + name
	if _, err := os.Stat(path); err != nil {
		execTemplate(w, "bad.html", "Empty twtxt for user.")
		return
	}
	http.ServeFile(w, r, path)
}

func main() {
	useHttps = false
	port := portDefault
	var err error
	if len(os.Args) > 1 {
		port, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal("Invalid port argument:", err)
		}
	}
	var certificateFile string
	var serverKeyFile string
	if len(os.Args) > 3 {
		useHttps = true
		log.Println("using TLS")
		certificateFile = os.Args[2]
		serverKeyFile = os.Args[3]
		if _, err := os.Stat(certificateFile); err != nil {
			log.Fatal("No certificate file found.")
		}
		if _, err := os.Stat(serverKeyFile); err != nil {
			log.Fatal("No server key file found.")
		}
	}
	createFileIfNotExists(loginsFile)
	// TODO: Handle err here.
	_ = os.Mkdir(twtsDir, 0700)
	secretKey := os.Getenv("KEY")
	if secretKey == "" {
		log.Fatal("No secret session key provided.")
	}
	store = sessions.NewCookieStore([]byte(secretKey))
	templ, err = template.New("main").ParseGlob("./templates/*.html")
	if err != nil {
		log.Fatal("Can't set up new template: ", err)
	}
	router := mux.NewRouter()
	router.HandleFunc("/", indexHandler)
	router.HandleFunc("/login", logInPostHandler).Methods("POST")
	router.HandleFunc("/signupform", signUpFormHandler)
	router.HandleFunc("/signup", signUpHandler).Methods("POST")
	router.HandleFunc("/logout", logOutHandler)
	router.HandleFunc("/twt", twtPostHandler).Methods("POST")
	router.HandleFunc("/twtxt/{name}", twtxtHandler)
	router.HandleFunc("/twtxt/", indexHandler)
	http.Handle("/", router)
	log.Println("serving at port", port)
	if useHttps {
		err = http.ListenAndServeTLS(":"+strconv.Itoa(port),
			certificateFile, serverKeyFile, nil)
	} else {
		err = http.ListenAndServe(":"+strconv.Itoa(port), nil)
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
