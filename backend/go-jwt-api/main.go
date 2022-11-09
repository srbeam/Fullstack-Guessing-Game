package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var hmacSampleSecret []byte

// Binding from JSON
type Register struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Fullname string `json:"fullname" binding:"required"`
}

type User struct {
	gorm.Model
	Username string
	Password string
	Fullname string
}

type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

var db *sql.DB

// func HandleFunc(w *http.ResponseWriter, c *http.Request) {
// 	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
// }

//	func handleArticles(w http.ResponseWriter, r *http.Request) {
//		enableCors(&w)
//		js, err := json.Marshal(Articles)
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusInternalServerError)
//			return
//		}
//		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
//		w.Write(js)
//	}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dsn := os.Getenv("MSQL_DNS")
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// Migrate the schema
	db.AutoMigrate(&User{})

	// orm.InitDB()
	r := gin.Default()

	r.POST("/register", func(c *gin.Context) {
		var json Register
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		//check user exists
		var userExist User
		db.Where("username = ?", json.Username).First(&userExist)
		if userExist.ID > 0 {
			c.JSON(400, gin.H{"status": "error", "message": "User Exists"})
			return
		}

		//Create User
		encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(json.Password), 10)
		user := User{Username: json.Username, Password: string(encryptedPassword), Fullname: json.Fullname}
		db.Create(&user) // pass pointer of data to Create

		if user.ID > 0 {
			c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Registered", "userId": user.ID})
		} else {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": "User Create Failed"})
		}
	})

	//endpoint /login
	r.POST("/login", func(c *gin.Context) {
		var json Login
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		//check user exists
		var userExist User
		db.Where("username = ?", json.Username).First(&userExist)
		if userExist.ID == 0 {
			c.JSON(401, gin.H{"status": "error", "message": "User Does Not Exists"})
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(userExist.Password), []byte(json.Password))
		if err == nil {
			hmacSampleSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"userId": userExist.ID,
			})
			// Sign and get the complete encoded token as a string using the secret
			tokenString, err := token.SignedString(hmacSampleSecret)
			fmt.Println(tokenString, err)

			c.JSON(201, gin.H{"status": "yes", "message": "Login Success", "token": tokenString})
		} else {
			c.JSON(401, gin.H{"status": "no", "message": "Login Failed"})
		}
	})

	// midleware
	// func Logger() gin.HandlerFunc {
	// 	func Logger (c *gin.Context) {
	// 	   hmacSampleSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
	// 	   header := c.Request.Header.Get("Authorization")
	// 	   tokenString := strings.ReplaceAll(header, "Bearer ", "")

	// 	   token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	// 		   if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	// 			   return nil, fmt.Errorf("Unexpected signing meyhod: %v", token.Header["alg"])
	// 		   }
	// 		   return hmacSampleSecret, nil
	// 	   })
	// 	   if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
	// 		   c.Set("userId", claims["userId"])
	// 		   // fmt.Println(claims["userId"])
	// 		   var users []User
	// 		   db.Find(&users)
	// 		   c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Read Success", "users": users})
	// 	   } else {
	// 		   c.JSON(400, gin.H{"status": "forbidden", "message": err.Error()})
	// 		   return
	// 	   }
	// 	   // before request
	// 	   c.Next()
	// 	}

	authorized := r.Group("/users")
	authorized.GET("/users", func(c *gin.Context) {
		hmacSampleSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
		header := c.Request.Header.Get("Authorization")
		tokenString := strings.ReplaceAll(header, "Bearer ", "")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing meyhod: %v", token.Header["alg"])
			}
			return hmacSampleSecret, nil
		})
		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// fmt.Println(claims["userId"])
			var users []User
			db.Find(&users)
			c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Read Success", "users": users})
		} else {
			c.JSON(400, gin.H{"status": "forbidden", "message": err.Error()})
			return
		}
	})

	r.GET("/guess", func(c *gin.Context) {
		hmacSampleSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
		header := c.Request.Header.Get("Authorization")
		tokenString := strings.ReplaceAll(header, "Bearer ", "")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing meyhod: %v", token.Header["alg"])
			}
			return hmacSampleSecret, nil
		})
		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// fmt.Println(claims["userId"])
			var users []User
			db.Find(&users)
			c.JSON(201, gin.H{"status": "ok", "message": "User can guess"})
		} else {
			c.JSON(400, gin.H{"status": "forbidden", "message": err.Error()})
			return
		}
	})

	// getAllUser
	r.GET("/users", func(c *gin.Context) {
		var users []User
		db.Find(&users)
		c.JSON(200, users)
		// c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "User Read Success", "users": users})

	})

	//getUserById
	r.GET("/users/:id", func(c *gin.Context) {
		id := c.Param("id")
		var user []User
		db.First(&user, id)
		c.JSON(200, user)
	})

	//createUserWithoutbcrypt
	// r.POST("/users", func(c *gin.Context) {
	// 	var user User
	// 	if err := c.ShouldBindJSON(&user); err != nil {
	// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	// 		return
	// 	}
	// 	result := db.Create(&user)
	// 	c.JSON(200, gin.H{"RowsAffected": result.RowsAffected})
	// })

	//delete user
	r.DELETE("/users/:id", func(c *gin.Context) {
		id := c.Param("id")
		var user []User
		db.First(&user, id)
		db.Delete(&user)
		c.JSON(200, user)
	})

	//update user
	r.PUT("/users", func(c *gin.Context) {
		var user User
		var updatedUser User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		db.First(&updatedUser, user.ID)
		updatedUser.Username = user.Username
		updatedUser.Password = user.Password
		updatedUser.Fullname = user.Fullname
		db.Save(updatedUser)
		c.JSON(200, updatedUser)
	})

	// r.Use(cors.Default()) //enable cors

	// config := cors.DefaultConfig()
	// config.AllowAllOrigins = true

	//  handleArticles(w http.ResponseWriter, r *http.Request) {
	// 	enableCors(&w)
	// 	js, err := json.Marshal(Articles)
	// 	if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// 	}
	// 	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	// 	w.Write(js)
	// 	}

	// r.Use(cors.New(cors.Config{
	// 	AllowOrigins:     []string{"http://localhost:3000"},
	// 	AllowMethods:     []string{"PUT", "POST", "GET"},
	// 	AllowHeaders:     []string{"Access-Control-Allow-Origin"},
	// 	ExposeHeaders:    []string{"Content-Length"},
	// 	AllowCredentials: true,
	// 	AllowOriginFunc: func(origin string) bool {
	// 		return origin == "https://github.com"
	// 	},
	// }))
	// CORSMiddleware()

	r.Run("localhost:8080")
}
