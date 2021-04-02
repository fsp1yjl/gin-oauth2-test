
package main

import (
	"context"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
)

var (
	config *Config
	globalToken *oauth2.Token
)
func init() {
	// todo 初始化 server , callback信息
	LoadConfig()
}

type  OAuth2Config struct{
	Server string
	LoginPath string
	AuthPath string
	TokenPath string
	ClientId string
	ClientSecret string
	Callback string
}
type Config struct {
	Host string
	Port string
	OAuth2 OAuth2Config
}


/*
   uos
	OAuth2 : OAuth2Config {
		Server: "http://localhost:9400",
		LoginPath: "/login",
		TokenPath: "/token",
		ClientId : "19abcf2774527faf5ae5ee1a9b316e7556bd9b78",
		ClientSecret: "664cbf97ebc94b4fe73e3ff8a7f2aeb9e6a91021",
		Callback: "http://localhost:9094/auth/callback",
	},
 */
func LoadConfig()  {

	config =  &Config{
		Host:"localhost",
		Port: "9094",
		OAuth2 : OAuth2Config {
			Server: "http://localhost:9096",
			LoginPath: "/oauth/authorize",
			TokenPath: "/oauth/token",
			ClientId : "19abcf2774527faf5ae5ee1a9b316e7556bd9b78",
			ClientSecret: "664cbf97ebc94b4fe73e3ff8a7f2aeb9e6a91021",
			Callback: "http://localhost:9094/auth/callback",
		},

	}


}

 // 初始化sessionStore
func initSessionStore() sessions.Store  {
	sessionStore := memstore.NewStore([]byte("SessionSecretKey"))
	return sessionStore
}

// 初始化服务器
func initServerControler() *gin.Engine{
	eng := gin.Default()
	eng.GET("/", DefaultPage)

	store := initSessionStore()
	eng.Use(sessions.Sessions("platform", store))


	auth := eng.Group("/auth")
	//auth.GET("/login", LoginHandle)
	auth.GET("/is_login", LoggedCheckHandle )
	auth.GET("/callback", CallbackHandle)


	return eng
}

func main() {
	s := initServerControler()
	s.Run(config.Host + ":" + config.Port) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func DefaultPage(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "hello",
	})
}

func LoginCheck(sess sessions.Session)  bool{
		token := sess.Get("token")
		if token == nil {
			return false
		}

		t := token.(oauth2.Token)

		if t.AccessToken != "" {
			fmt.Println("TOKEN:", t)
			return true
		}

		return false
}

//判断是否登录中
func LoggedCheckHandle(c *gin.Context)  {
	session := sessions.Default(c)

	// todo 判断session中是否存在token ,如果存在则直接返回
	logged := LoginCheck(session)
	state := "hello"

	var getQueryString  func() string
	getQueryString = func () string  {
		str := fmt.Sprintf("?response_type=code&client_id=%v&redirect_uri=%v&state=%v", config.OAuth2.ClientId, config.OAuth2.Callback, state)
		fmt.Println("str4----------:", str)
		return str
	}

	if logged {
		c.Redirect(302, "/")
		return
	}

	session.Set("state", state )
	session.Save()
	c.Redirect(302, config.OAuth2.Server + config.OAuth2.LoginPath + getQueryString())
	return



}

// 需要认证，跳转到认证页面
//func LoginHandle(c *gin.Context) {
//	// todo 判断session中是否存在token ,如果存在则直接返回
//
//
//}

func CallbackHandle(c *gin.Context) {
	r := c.Request
	r.ParseForm()

	session := sessions.Default(c)
	stateSession := session.Get("state" )
	state := r.Form.Get("state")

	// nsrf secure check by state param
	if state == "" || state != stateSession {
		c.JSON(200,gin.H{"msg:":"nsrf check failed"})
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(c.Writer, "Code not found", http.StatusBadRequest)
		return
	}

	authConf := oauth2.Config{
		ClientID:     "222222",
		ClientSecret: "22222222",
		Scopes:       []string{"all"},
		RedirectURL:  "http://localhost:9094/oauth2",
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.OAuth2.Server + "/oauth/authorize",
			TokenURL: config.OAuth2.Server + "/oauth/token",
		},
	}


	fmt.Println("1111 before get token")
	// exchange 获取token
	token, err := authConf.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(500, gin.H{"msg:": "internal error"})
		return
	}
	fmt.Println("222 after  get token")

	session.Set("token", token )
	session.Save()
	c.Redirect(200,"/auth/is_login")


}