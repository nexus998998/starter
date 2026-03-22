package main

import (
	"fmt"
	"starter/hash"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

type users struct {
	gorm.Model
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

type sessions struct {
	gorm.Model
	SessionID string `gorm:"unique"`
	UserID    int
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

	results := db.Select("user_id").First(&session, "session_id = ?", hashedSessionID)

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

func login(username string, password string) (string, error) {
	var user users
	hashedPassword, err := hash.HashString(password)

	if err != nil {
		return "", err
	}

	results := db.Select("id").Where("username = ? AND password = ?", username, hashedPassword).First(&user)
	if results.Error != nil {
		if results.Error == gorm.ErrRecordNotFound {
			return "", results.Error
		}
		return "", results.Error
	}

	sessionID, err := hash.GenerateRandomString(12)
	if err != nil {
		return "", err
	}
	hashedSessionID, err := hash.HashString(sessionID)

	session := sessions{
		UserID:    int(user.ID),
		SessionID: hashedSessionID,
	}

	results = db.Create(&session)

	if results.Error != nil {
		return "", results.Error
	}

	return sessionID, nil
}

func signup(username string, password string) (string, error) {

	hashedPassword, err := hash.HashString(password)

	if err != nil {
		return "", err
	}

	user := users{
		Username: username,
		Password: hashedPassword,
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
	}

	if err := db.Create(&session).Error; err != nil {
		return "", err
	}

	return sessionID, nil
}

func main() {

	var err error

	db, err = gorm.Open(postgres.Open("host=localhost port=5432 password=locally dbname=starter user=postgres"), &gorm.Config{
		TranslateError: true,
	})
	if err != nil {
		panic(err)
	}

	db.AutoMigrate(&users{})
	db.AutoMigrate(&sessions{})

	engine := html.New("templates", ".html")

	app := fiber.New(fiber.Config{Views: engine})

	fmt.Println("running")

	app.Post("/login", func(c *fiber.Ctx) error {

		username := c.FormValue("username")
		password := c.FormValue("password")

		if username == "" || password == "" {
			return c.Redirect("/login?message=username+or+password+must+not+be+blank", fiber.StatusFound)
		}

		if containsSpace(username) || containsSpace(password) {
			return c.Redirect("/login?message=username+or+password+must+not+contain+spaces+!", fiber.StatusFound)
		}

		fmt.Println(username, password)

		sessionID, err := login(username, password)

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Redirect("/login?message=username+or+password+is+not+correct+!", fiber.StatusFound)
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

	app.Post("/signup", func(c *fiber.Ctx) error {

		username := c.FormValue("username")
		password := c.FormValue("password")

		if username == "" || password == "" {
			return c.Redirect("/signup?message=username+or+password+must+not+be+blank", fiber.StatusFound)
		}

		if containsSpace(username) || containsSpace(password) {
			return c.Redirect("/signup?message=username+or+password+must+not+contain+spaces+!", fiber.StatusFound)
		}

		fmt.Println(username, password)

		sessionID, err := signup(username, password)

		if err != nil {
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

	protected := app.Group("", authenticate)

	protected.Get("/", func(c *fiber.Ctx) error {
		return c.Render("mainPage", fiber.Map{
			"user": c.Locals("user").(users),
		})
	})

	app.Listen(":8080")
}
