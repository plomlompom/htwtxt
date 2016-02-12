package main

import "bufio"
import "crypto/rand"
import "encoding/base64"
import "golang.org/x/crypto/bcrypt"
import "gopkg.in/gomail.v2"
import "log"
import "github.com/gorilla/mux"
import "net/http"
import "os"
import "strconv"
import "strings"
import "time"

func passwordResetRequestGetHandler(w http.ResponseWriter, r *http.Request) {
	if "" == mailuser {
		execTemplate(w, "nopwresetrequest.html", "")
	} else {
		execTemplate(w, "pwresetrequest.html", "")
	}
}

func passwordResetRequestPostHandler(w http.ResponseWriter, r *http.Request) {
	preparePasswordReset := func(name string) {
		if "" == mailuser {
			return
		}
		now := int(time.Now().Unix())
		tokens, errWait := getFromFileEntryFor(pwResetWaitPath, name, 2)
		if errWait == nil {
			lastTime, err := strconv.Atoi(tokens[0])
			if err != nil {
				log.Fatal("Trouble parsing password reset "+
					"wait times", err)
			}
			if lastTime+resetWaitTime >= now {
				return
			}
		}
		var target string
		tokens, err := getFromFileEntryFor(loginsPath, name, 5)
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
		strTime := strconv.Itoa(now)
		appendToFile(pwResetPath, urlPart+"\t"+name+"\t"+strTime)
		m := gomail.NewMessage()
		m.SetHeader("From", mailuser)
		m.SetHeader("To", target)
		m.SetHeader("Subject", "password reset link")
		msg := myself + "/passwordreset/" + urlPart
		m.SetBody("text/plain", msg)
		if err := dialer.DialAndSend(m); err != nil {
			log.Fatal("Can't send mail", err)
		}
		line := name + "\t" + strTime
		if nil == errWait {
			replaceLineStartingWith(pwResetWaitPath, name, line)
		} else {
			appendToFile(pwResetWaitPath, line)
		}
	}
	go preparePasswordReset(r.FormValue("name"))
	http.Redirect(w, r, "/", 302)
}

func passwordResetLinkGetHandler(w http.ResponseWriter, r *http.Request) {
	urlPart := mux.Vars(r)["secret"]
	tokens, err := getFromFileEntryFor(pwResetPath, urlPart, 3)
	if err != nil {
		http.Redirect(w, r, "/404", 302)
		return
	}
	createTime, err := strconv.Atoi(tokens[1])
	if err != nil {
		log.Fatal("Can't read time from pw reset file", err)
	}
	if createTime+resetLinkExp < int(time.Now().Unix()) {
		http.Redirect(w, r, "/404", 302)
		return
	}
	name := tokens[0]
	tokensUser, err := getFromFileEntryFor(loginsPath, name,
		5)
	if err != nil {
		log.Fatal("Can't read from loings file", err)
	}
	if "" != tokensUser[2] {
		type data struct {
			Secret   string
			Question string
		}
		err := templ.ExecuteTemplate(w,
			"pwresetquestion.html", data{
				Secret:   urlPart,
				Question: tokensUser[2]})
		if err != nil {
			log.Fatal("Trouble executing template", err)
		}
		return
	}
	execTemplate(w, "pwreset.html", urlPart)
}

func passwordResetLinkPostHandler(w http.ResponseWriter, r *http.Request) {
	urlPart := mux.Vars(r)["secret"]
	name := r.FormValue("name")
	tokens, err := getFromFileEntryFor(pwResetPath, urlPart, 3)
	if err != nil {
		http.Redirect(w, r, "/404", 302)
		return
	}
	createTime, err := strconv.Atoi(tokens[1])
	if err != nil {
		log.Fatal("Can't read time from pw reset file", err)
	}
	if createTime+resetLinkExp < int(time.Now().Unix()) {
		http.Redirect(w, r, "/404", 302)
		return
	}
	if tokens[0] != name {
		execTemplate(w, "error.html", "Wrong answer(s).")
		removeLineStartingWith(pwResetPath, urlPart)
		return
	}
	tokensUser, err := getFromFileEntryFor(loginsPath, name, 5)
	if err != nil {
		log.Fatal("Can't get entry for user", err)
	}
	if "" != tokensUser[2] &&
		nil != bcrypt.CompareHashAndPassword([]byte(tokensUser[3]),
			[]byte(r.FormValue("secanswer"))) {
		execTemplate(w, "error.html", "Wrong answer(s).")
		removeLineStartingWith(pwResetPath, urlPart)
		return
	}
	hash, err := newPassword(w, r)
	if err != nil {
		execTemplate(w, "error.html", err.Error())
		return
	}
	tokensUser[0] = hash
	line := name + "\t" + strings.Join(tokensUser, "\t")
	replaceLineStartingWith(loginsPath, tokens[0], line)
	removeLineStartingWith(pwResetPath, urlPart)
	execTemplate(w, "feedset.html", "")
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
	name := r.FormValue("name")
	if "" == name || !onlyLegalRunes(name) || len(name) > 140 {
		execTemplate(w, "error.html", "Illegal name.")
		return
	}
	if _, err := getFromFileEntryFor(loginsPath, name, 5); err == nil {
		execTemplate(w, "error.html", "Username taken.")
		return
	}
	hash, err := newPassword(w, r)
	if err != nil {
		execTemplate(w, "error.html", err.Error())
		return
	}
	mail := ""
	if "" != r.FormValue("mail") {
		mail, err = newMailAddress(w, r)
		if err != nil {
			execTemplate(w, "error.html", err.Error())
			return
		}
	}
	var secquestion, secanswer string
	if "" != r.FormValue("secquestion") || "" != r.FormValue("secanswer") {
		secquestion, secanswer, err = newSecurityQuestion(w, r)
		if err != nil {
			execTemplate(w, "error.html", err.Error())
			return
		}
	}
	appendToFile(loginsPath,
		name+"\t"+hash+"\t"+mail+"\t"+secquestion+"\t"+secanswer)
	execTemplate(w, "feedset.html", "")
}

func accountSetPwHandler(w http.ResponseWriter, r *http.Request) {
	changeLoginField(w, r, newPassword, 0)
}

func accountSetMailHandler(w http.ResponseWriter, r *http.Request) {
	changeLoginField(w, r, newMailAddress, 1)
}

func accountSetQuestionHandler(w http.ResponseWriter, r *http.Request) {
	name, err := login(w, r)
	if err != nil {
		return
	}
	var secquestion, secanswer string
	if "" != r.FormValue("secquestion") || "" != r.FormValue("secanswer") {
		secquestion, secanswer, err = newSecurityQuestion(w, r)
		if err != nil {
			execTemplate(w, "error.html", err.Error())
			return
		}
	}
	tokens, err := getFromFileEntryFor(loginsPath, name, 5)
	if err != nil {
		log.Fatal("Can't get entry for user", err)
	}
	tokens[2] = secquestion
	tokens[3] = secanswer
	replaceLineStartingWith(loginsPath, name,
		name+"\t"+strings.Join(tokens, "\t"))
	execTemplate(w, "feedset.html", "")
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	file := openFile(loginsPath)
	defer file.Close()
	scanner := bufio.NewScanner(bufio.NewReader(file))
	var dir []string
	tokens := tokensFromLine(scanner, 5)
	for 0 != len(tokens) {
		dir = append(dir, tokens[0])
		tokens = tokensFromLine(scanner, 5)
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

func handleRoutes() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/", handleTemplate("index.html", ""))
	router.HandleFunc("/feeds", listHandler).Methods("GET")
	router.HandleFunc("/feeds/", listHandler)
	router.HandleFunc("/accountsetquestion",
		handleTemplate("accountsetquestion.html", "")).Methods("GET")
	router.HandleFunc("/accountsetquestion", accountSetQuestionHandler).
		Methods("POST")
	router.HandleFunc("/accountsetmail",
		handleTemplate("accountsetmail.html", "")).Methods("GET")
	router.HandleFunc("/accountsetmail", accountSetMailHandler).
		Methods("POST")
	router.HandleFunc("/accountsetpw", handleTemplate("accountsetpw.html",
		"")).Methods("GET")
	router.HandleFunc("/accountsetpw", accountSetPwHandler).Methods("POST")
	router.HandleFunc("/account", handleTemplate("account.html", ""))
	router.HandleFunc("/signup", signUpFormHandler).Methods("GET")
	router.HandleFunc("/signup", signUpHandler).Methods("POST")
	router.HandleFunc("/feeds", twtxtPostHandler).Methods("POST")
	router.HandleFunc("/feeds/{name}", twtxtHandler)
	router.HandleFunc("/info", handleTemplate("info.html", contact))
	router.HandleFunc("/passwordreset", passwordResetRequestPostHandler).
		Methods("POST")
	router.HandleFunc("/passwordreset", passwordResetRequestGetHandler).
		Methods("GET")
	router.HandleFunc("/passwordreset/{secret}",
		passwordResetLinkGetHandler).Methods("GET")
	router.HandleFunc("/passwordreset/{secret}",
		passwordResetLinkPostHandler).Methods("POST")
	router.HandleFunc("/style.css",
		func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, templPath+"/style.css")
		})
	return router
}
