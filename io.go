// htwtxt – hosted twtxt server; see README for copyright and license info

package main

import "bufio"
import "errors"
import "log"
import "os"
import "strings"
import "io/ioutil"

const loginsFile = "logins.txt"
const feedsDir = "feeds"
const ipDelaysFile = "ip_delays.txt"
const pwResetFile = "password_reset.txt"
const pwResetWaitFile = "password_reset_wait.txt"

var certPath string
var dataDir string
var feedsPath string
var ipDelaysPath string
var keyPath string
var loginsPath string
var pwResetPath string
var pwResetWaitPath string
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
		tokens := strings.Split(line, "\t")
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
		tokens := strings.Split(line, "\t")
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
	tokens := strings.Split(line, "\t")
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
		tokens = tokensFromLine(scanner, numberTokensExpected)
	}
	return []string{}, errors.New("")
}

func initFilesAndDirs() {
	log.Println("Using as templates dir:", templPath)
	log.Println("Using as data dir:", dataDir)
	loginsPath = dataDir + "/" + loginsFile
	feedsPath = dataDir + "/" + feedsDir
	ipDelaysPath = dataDir + "/" + ipDelaysFile
	pwResetPath = dataDir + "/" + pwResetFile
	pwResetWaitPath = dataDir + "/" + pwResetWaitFile
	if "" != keyPath {
		log.Println("Using TLS.")
		if _, err := os.Stat(certPath); err != nil {
			log.Fatal("No certificate file found.")
		}
		if _, err := os.Stat(keyPath); err != nil {
			log.Fatal("No server key file found.")
		}
	}
	createFileIfNotExists(loginsPath)
	createFileIfNotExists(pwResetPath)
	createFileIfNotExists(pwResetWaitPath)
	createFileIfNotExists(ipDelaysPath)
	// TODO: Handle err here.
	_ = os.Mkdir(feedsPath, 0700)
}
