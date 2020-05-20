package main

import (
	"html/template"
	"net/http"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Name       string
	Email      string
	Password   []byte
	AgreeTerms string
}

var dbUsers = map[string]user{}      // user ID, user
var dbSessions = map[string]string{} // session ID, user ID

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func index(w http.ResponseWriter, r *http.Request) {
	u := getUser(w, r)
	tpl.ExecuteTemplate(w, "index.html", u)

}

func signUp(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(r) {
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	// Process form submission
	if r.Method == http.MethodPost {

		// Get form values
		fn := r.FormValue("name")
		em := r.FormValue("email")
		pw := r.FormValue("pass")
		rpw := r.FormValue("re_pass")
		at := r.FormValue("agree-term")

		// Email already registered?
		if _, ok := dbUsers[em]; ok {
			http.Error(w, "Email already registered!", http.StatusForbidden)
			return
		}

		if fn == "" {
			http.Error(w, "Please enter your name!", http.StatusForbidden)
			return
		}

		if pw == "" || rpw == "" {
			http.Error(w, "Please enter password!", http.StatusForbidden)
			return
		}

		// Password did not match
		if pw != rpw {
			http.Error(w, "Password did not match!", http.StatusForbidden)
			return
		}

		// Agree Terms and Conditions
		if at == "" {
			http.Error(w, "Please agree Terms and Conditions to continue!", http.StatusForbidden)
			return
		}

		// Create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		dbSessions[c.Value] = em

		// Store user in dbUser
		bs, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		u := user{fn, em, bs, at}
		dbUsers[em] = u

		// Redirect
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return

	}

	tpl.ExecuteTemplate(w, "signup.html", nil)
}

func logIn(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(r) {
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	// Process form submission
	if r.Method == http.MethodPost {
		em := r.FormValue("email")
		pw := r.FormValue("your_pass")

		//  Is there that email?
		u, ok := dbUsers[em]
		if !ok {
			http.Error(w, "Username or/and password do not match!", http.StatusForbidden)
			return
		}

		// Is password correct?
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(pw))
		if err != nil {
			http.Error(w, "Username or/and password do not match!", http.StatusForbidden)
			return
		}

		// Create session
		sID, _ := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)
		dbSessions[c.Value] = em
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "login.html", nil)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if !alreadyLoggedIn(r) {
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	c, _ := r.Cookie("session")

	// Delete the session
	delete(dbSessions, c.Value)

	// Remove the cookie
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}

	http.SetCookie(w, c)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func main() {

	fs := http.FileServer(http.Dir("templates"))
	http.Handle("/images/", fs)

	http.Handle("/favicon.ico", http.NotFoundHandler())

	http.HandleFunc("/", logIn)
	http.HandleFunc("/signup", signUp)
	http.HandleFunc("/index", index)
	http.HandleFunc("/logout", logout)

	http.ListenAndServe(":8080", nil)
}
