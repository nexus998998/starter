package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"starter/hash"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var cost = 12
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
var appPassword string
var engine *html.Engine

type users struct {
	gorm.Model
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
	Email    string `gorm:"unique;not null"`
}

type sessions struct {
	gorm.Model
	SessionID string `gorm:"unique"`
	UserID    int
	Verified  bool
	Expires   time.Time
}

type token struct {
	gorm.Model
	TokenID   string `gorm:"unique;not null"`
	SessionID int    `gorm:"not null"`
	Expires   time.Time
}

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func sendVerificationCode(to string, code string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "radon88998@gmail.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", "login to your account !")

	buffer := new(bytes.Buffer)
	err := engine.Render(buffer, "verificationEmail", fiber.Map{
		"VerificationCode": code,
	})

	if err != nil {
		return err
	}

	m.SetBody("text/html", buffer.String())

	d := gomail.NewDialer("smtp.gmail.com", 587, "radon88998@gmail.com", "dmknwmonvmtovxnr")
	return d.DialAndSend(m)
}

func containsSpace(s string) bool {
	for _, char := range s {
		if char == rune(' ') {
			return true
		}
	}

	return false
}

func authenticate(c *fiber.Ctx) error {
	sessionID := c.Cookies("sessionID")

	if sessionID == "" {
		return c.Redirect("/login?message=you+must+login+first+!", fiber.StatusFound)
	}

	hashedSessionID, err := hash.HashString(sessionID)

	if err != nil {
		fmt.Println(err)
		return err
	}

	var session sessions

	results := db.Select("user_id").First(&session, "session_id = ? AND verified = TRUE ", hashedSessionID)

	if results.Error != nil {
		if results.Error == gorm.ErrRecordNotFound {
			return c.Redirect(
				"/login?message=you+must+login+first", fiber.StatusFound,
			)
		}
		return results.Error
	}

	var user users
	results = db.First(&user, "id = ?", session.UserID)

	if results.Error != nil {
		return results.Error
	}

	c.Locals("user", user)

	return c.Next()
}

func login(email string, password string) (string, error) {
	var user users

	results := db.Select("id", "password").Where("email = ? ", email).First(&user)
	if results.Error != nil {
		if results.Error == gorm.ErrRecordNotFound {
			return "", results.Error
		}
		return "", results.Error
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {
		return "", err
	}

	sessionID, err := hash.GenerateRandomString(12)
	if err != nil {
		return "", err
	}
	hashedSessionID, err := hash.HashString(sessionID)

	session := sessions{
		UserID:    int(user.ID),
		SessionID: hashedSessionID,
		Verified:  true,
	}

	results = db.Create(&session)

	if results.Error != nil {
		return "", results.Error
	}

	return sessionID, nil
}

func makeLoginToken(email string) (string, error) {
	expire := time.Now().Add(30 * 60 * time.Second)

	// take the email and find the user from it
	var user users
	results := db.First(&user, "email = ?", email)
	if results.Error != nil {
		return "", results.Error
	}

	// make an unverified session
	sessionID, err := hash.GenerateRandomString(12)
	if err != nil {
		return "", err
	}

	hashedSession, err := hash.HashString(sessionID)

	if err != nil {
		return "", err
	}

	session := sessions{
		SessionID: hashedSession,
		UserID:    int(user.ID),
		Verified:  false,
		Expires:   expire,
	}

	results = db.Create(&session)
	if results.Error != nil {
		return "", results.Error
	}

	// make a token and hash it
	tokenID, err := hash.GenerateRandomString(12)
	if err != nil {
		return "", err
	}

	hashedTokenID, err := hash.HashString(tokenID)
	if err != nil {
		return "", err
	}

	token := token{
		Expires:   expire,
		TokenID:   hashedTokenID,
		SessionID: int(session.ID),
	}

	db.Create(&token)

	err = sendVerificationCode(email, tokenID)

	if err != nil {
		return "", err
	}

	return sessionID, nil

}

func signup(username string, password string, email string) (string, error) {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)

	if err != nil {
		return "", err
	}

	if !isValidEmail(email) {
		return "", fiber.ErrBadRequest
	}

	user := users{
		Username: username,
		Password: string(hashedPassword),
		Email:    email,
	}

	if err := db.Create(&user).Error; err != nil {
		return "", err
	}

	sessionID, err := hash.GenerateRandomString(12)

	if err != nil {
		return "", err
	}

	hashedSessionID, err := hash.HashString(sessionID)

	if err != nil {
		return "", err
	}

	session := sessions{
		UserID:    int(user.ID),
		SessionID: hashedSessionID,
		Verified:  true,
	}

	if err := db.Create(&session).Error; err != nil {
		return "", err
	}

	return sessionID, nil
}

func verify(tokenID string) error {

	fmt.Println("verifying")

	hashedTokenID, err := hash.HashString(tokenID)

	if err != nil {
		return err
	}

	var Token token
	results := db.Select("session_id").First(&Token, "token_id = ? ", hashedTokenID)

	if results.Error != nil {
		return results.Error
	}

	results = db.Model(&sessions{}).Where("id = ?", Token.SessionID).Update("verified", true)
	fmt.Println(results.RowsAffected)
	if results.Error != nil {
		return results.Error
	}
	return nil
}

func dbWipe() {
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM sessions")
	db.Exec("DELETE FROM tokens")
}

func main() {

	var err error

	db, err = gorm.Open(postgres.Open("host=localhost port=5432 password=locally dbname=starter user=postgres"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		panic(err)
	}

	//delete in production ofcourse
	dbWipe()

	db.AutoMigrate(&users{})
	db.AutoMigrate(&sessions{})
	db.AutoMigrate(&token{})

	engine = html.New("templates", ".html")

	app := fiber.New(fiber.Config{Views: engine})

	appPassword = os.Getenv("appPassword")

	if appPassword == "" {
		panic("app password was not assigned")
	}

	fmt.Println("is it really running at this point ? ")

	app.Post("/login", func(c *fiber.Ctx) error {

		email := c.FormValue("email")
		password := c.FormValue("password")

		if email == "" || password == "" {
			return c.Redirect("/login?message=email+or+password+must+not+be+blank", fiber.StatusFound)
		}

		if containsSpace(email) || containsSpace(password) {
			return c.Redirect("/login?message=email+or+password+must+not+contain+spaces+!", fiber.StatusFound)
		}

		fmt.Println(email, password)

		sessionID, err := login(email, password)

		if err != nil {
			if err == gorm.ErrRecordNotFound || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return c.Redirect("/login?message=email+or+password+is+not+correct+!", fiber.StatusFound)
			}
			fmt.Println(err)
			return err
		}

		c.Cookie(&fiber.Cookie{
			Name:  "sessionID",
			Value: sessionID,
			// Expires:  time.Now().Add(365 * 60 * 60 * time.Second), uncomment on deployment
			HTTPOnly: true,
		})

		return c.Redirect("/", fiber.StatusFound)
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		return c.Render("login", fiber.Map{
			"ErrorMessage": c.Query("message", ""),
		})
	})

	app.Get("/signup", func(c *fiber.Ctx) error {
		return c.Render("signup", fiber.Map{
			"ErrorMessage": c.Query("message", ""),
		})
	})

	app.Get("/forgotPassword", func(c *fiber.Ctx) error {
		return c.Render("forgotPassword", fiber.Map{
			"ErrorMessage": c.Query("message", ""),
		})
	})

	app.Post("/forgotPassword", func(c *fiber.Ctx) error {
		email := strings.TrimSpace(c.FormValue("email"))
		if email == "" {
			return c.Redirect("/forgotPassword?message=email+must+not+be+blank", fiber.StatusFound)
		}

		if containsSpace(email) {
			return c.Redirect("/forgotPassword?message=email+must+not+contain+spaces", fiber.StatusFound)
		}

		sessionID, err := makeLoginToken(email)

		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return c.Redirect("/forgotPassword?message=account+not+found!", fiber.StatusFound)
			}

			fmt.Println(err)

			return err
		}

		c.Cookie(&fiber.Cookie{
			Name:     "sessionID",
			Value:    sessionID,
			HTTPOnly: true,
			// Expires:  time.Now().Add(365 * 60 * 60 * time.Second), uncomment on deployment
		})

		return c.Redirect("/verify", fiber.StatusFound)
	})

	app.Post("/signup", func(c *fiber.Ctx) error {

		username := strings.TrimSpace(c.FormValue("username"))
		password := strings.TrimSpace(c.FormValue("password"))
		email := strings.TrimSpace(c.FormValue("email"))

		if username == "" || password == "" || email == "" {
			return c.Redirect("/signup?message=username+or+password+must+not+be+blank", fiber.StatusFound)
		}

		if containsSpace(username) || containsSpace(password) || containsSpace(email) {
			return c.Redirect("/signup?message=username+or+or+email+password+must+not+contain+spaces+!", fiber.StatusFound)
		}

		fmt.Println(username, password, email)

		sessionID, err := signup(username, password, email)

		if err != nil {
			if errors.Is(err, fiber.ErrBadRequest) {
				return c.Redirect("/signup?message=email+address+not+valid")
			}
			if err == gorm.ErrDuplicatedKey {
				return c.Redirect("/login?message=this+user+already+exists+,+do+you+want+to+login+?", fiber.StatusFound)
			}
			fmt.Println(err)
			return err
		}

		c.Cookie(&fiber.Cookie{
			Name:  "sessionID",
			Value: sessionID,
			// Expires:  time.Now().Add(365 * 60 * 60 * time.Second), uncomment on deployment
			HTTPOnly: true,
		})

		return c.Redirect("/", fiber.StatusFound)
	})

	app.Get("/verify", func(c *fiber.Ctx) error {
		return c.Render("waitForVerification", fiber.Map{
			"ErrorMessage": c.Query("message", ""),
		})
	})

	app.Post("/verify", func(c *fiber.Ctx) error {
		Token := strings.TrimSpace(c.FormValue("token"))
		if Token == "" {
			return c.Redirect("/forgotPassword?message=shouldn't+be+blank")
		}

		fmt.Println("hello i am here ")

		if err := verify(Token); err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Redirect("/forgotPassword?message=your+code+isn't+correct+or+expired+please+try+again")
			}

			fmt.Println(err)
			return err
		}

		return c.Redirect("/?message=logged+in+successfully", fiber.StatusFound)

	})

	protected := app.Group("", authenticate)

	protected.Get("/", func(c *fiber.Ctx) error {
		return c.Render("mainPage", fiber.Map{
			"user": c.Locals("user").(users),
		})
	})

	app.Listen(":8080")

	go func() {
		for {
			time.Sleep(20 * 60 * time.Second)
			results := db.Where("expiree < ?", time.Now()).Delete(&token{})
			if results.Error != nil {
				panic(results.Error)
			}
			results = db.Where("expiree < ?", time.Now()).Delete(&sessions{})
			if results.Error != nil {
				panic(results.Error)

			}
		}
	}()
}
